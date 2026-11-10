# -*- coding: utf-8 -*-
# Security regression tests for the SPNEGO mechListMIC handling in NegotiateProxy.
#
# These tests build fully offline SPNEGO negotiation traces using deterministic fake inner mechanisms together with
# real mechListMIC sign/verify computations. They prove that receiving negState accept-complete never causes the
# negotiation to skip a mechListMIC that RFC 4178 requires, covering mechanism list tampering, reordering, acceptor
# re-selection, missing/wrong MICs, OID aliases and the legacy responseToken == mechListMIC compatibility branch.

import hmac
import socket
import typing

import pytest

import spnego
import spnego._spnego as sp
from spnego._context import ContextProxy, ContextReq, GSSMech, UnwrapResult, WrapResult
from spnego._negotiate import NegotiateProxy
from spnego.exceptions import BadMICError, InvalidTokenError, NoContextError

# A fixed key shared by the fake mechanisms. The mechListMIC is a real keyed MAC over the DER encoded MechTypeList,
# so tampering with the list the two peers confirm changes the digest and fails verification.
FAKE_SESSION_KEY = b"\x10" * 16


class FakeMechContext(ContextProxy):
    """A stand-in inner mechanism that completes in one round trip and computes real keyed MICs.

    The mechanism tracks its own completion independently of the outer SPNEGO layer, which lets the tests assert both
    states separately: the inner context can hold session keys (and be "complete") while the outer negotiation must
    still refuse wrap/unwrap until the mechListMIC has been verified.
    """

    PROTOCOL = "kerberos"

    def __init__(self, usage: str = "initiate") -> None:
        super().__init__(
            [spnego.CredentialCache()],
            None,
            None,
            None,
            ContextReq.default,
            usage,
            self.PROTOCOL,
            spnego.NegotiateOptions.none,
        )
        self._inner_complete = False
        self.steps: typing.List[typing.Optional[bytes]] = []

    @classmethod
    def available_protocols(cls, options=None) -> typing.List[str]:
        return [cls.PROTOCOL]

    @property
    def client_principal(self) -> None:
        return None

    @property
    def complete(self) -> bool:
        return self._inner_complete

    @property
    def negotiated_protocol(self) -> str:
        return self.PROTOCOL

    @property
    def session_key(self) -> bytes:
        return FAKE_SESSION_KEY

    def new_context(self) -> "FakeMechContext":
        return type(self)(self.usage)

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        self.steps.append(in_token)
        if self.usage == "accept":
            self._inner_complete = True
            return b"MECH-REPLY"

        if in_token:
            self._inner_complete = True
            return None

        return b"MECH-REQUEST"

    def wrap(self, data, encrypt=True, qop=None) -> WrapResult:
        # A deterministic, reversible transform so round trips can be asserted without a real security provider.
        return WrapResult(data=b"WRAP(" + data + b")", encrypted=bool(encrypt))

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_winrm(self, data):
        raise NotImplementedError()

    def unwrap(self, data) -> UnwrapResult:
        assert data.startswith(b"WRAP(") and data.endswith(b")")
        return UnwrapResult(data=data[5:-1], encrypted=True, qop=0)

    def unwrap_iov(self, iov):
        raise NotImplementedError()

    def unwrap_winrm(self, header, data):
        raise NotImplementedError()

    def sign(self, data, qop=None) -> bytes:
        return hmac.new(FAKE_SESSION_KEY, data, "sha256").digest()

    def verify(self, data, mic) -> int:
        expected = hmac.new(FAKE_SESSION_KEY, data, "sha256").digest()
        if not hmac.compare_digest(expected, mic):
            raise InvalidTokenError(context_msg="Fake mech mechListMIC verification failed")
        return 0

    @property
    def _context_attr_map(self):
        return []


def _mech_list_mic(mech_list: typing.List[str]) -> bytes:
    """Compute a mechListMIC exactly the way the NegotiateProxy signs the DER encoded MechTypeList."""
    return hmac.new(FAKE_SESSION_KEY, sp.pack_mech_type_list(mech_list), "sha256").digest()


def _initiator(mech: GSSMech = GSSMech.kerberos) -> NegotiateProxy:
    return NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={mech: FakeMechContext("initiate")},
    )


def _unpack(token: bytes):
    return sp.unpack_token(token)


def _assert_not_usable(context: NegotiateProxy) -> None:
    """A rejected negotiation must report incomplete and refuse per-message protection."""
    assert context.complete is False
    with pytest.raises(NoContextError):
        context.wrap(b"secret")
    with pytest.raises(NoContextError):
        context.unwrap(b"WRAP(secret)")


def _assert_usable(context: NegotiateProxy) -> None:
    wrapped = context.wrap(b"secret")
    assert wrapped.data == b"WRAP(secret)"
    assert context.unwrap(wrapped.data).data == b"secret"


def test_happy_path_mechlistmic_completes_and_protects_messages():
    # Full RFC 4178 MIC exchange over a non-preferred selection. Both peers confirm the same original mechanism list.
    client = _initiator()
    init = _unpack(client.step())
    assert isinstance(init, sp.NegTokenInit)
    offered = init.mech_types
    assert init.mech_token == b"MECH-REQUEST"

    # Acceptor re-selects the (only) mech and explicitly requests a MIC, providing its own over the offered list.
    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
        mech_list_mic=_mech_list_mic(offered),
    ).pack()
    client_mic_token = client.step(request_mic)
    client_mic_resp = _unpack(client_mic_token)

    # Outer negotiation is NOT complete after the first MIC leg; the initiator waits for accept-complete.
    assert client.complete is False
    assert client._mic_sent is True
    assert client._mic_recv is True
    assert client._context.complete is True  # Inner mechanism finished, but the outer layer has not.
    assert client_mic_resp.mech_list_mic == _mech_list_mic(offered)

    accept_complete = sp.NegTokenResp(neg_state=sp.NegState.accept_complete).pack()
    assert client.step(accept_complete) is None
    assert client.complete is True
    _assert_usable(client)


def test_tampered_mech_list_mic_is_rejected():
    # The acceptor's MIC was computed over a different (tampered) MechTypeList than the initiator offered.
    client = _initiator()
    offered = _unpack(client.step()).mech_types

    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
        mech_list_mic=_mech_list_mic([GSSMech.ntlm.value]),  # MIC over a list the initiator never sent.
    ).pack()
    with pytest.raises(InvalidTokenError, match="mechListMIC verification failed"):
        client.step(request_mic)

    _assert_not_usable(client)


def test_wrong_mic_bytes_are_rejected():
    # A structurally present but incorrect MIC (e.g. attacker recomputed without the shared key) must be rejected.
    client = _initiator()
    offered = _unpack(client.step()).mech_types

    good_mic = _mech_list_mic(offered)
    wrong_mic = bytes(b ^ 0xFF for b in good_mic)
    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
        mech_list_mic=wrong_mic,
    ).pack()
    with pytest.raises(InvalidTokenError, match="mechListMIC verification failed"):
        client.step(request_mic)

    _assert_not_usable(client)


def test_missing_mic_after_request_mic_is_rejected():
    # Once the acceptor requested a MIC, an accept-complete without any mechListMIC cannot establish the context.
    client = _initiator()
    client.step()

    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
    ).pack()
    client.step(request_mic)
    assert client._mic_requested is True
    assert client.complete is False

    accept_complete = sp.NegTokenResp(neg_state=sp.NegState.accept_complete).pack()
    with pytest.raises(InvalidTokenError, match="without the required mechListMIC"):
        client.step(accept_complete)

    _assert_not_usable(client)


def test_accept_complete_alone_does_not_skip_required_mic():
    # The original vulnerability: accept-complete arriving while a MIC exchange is active must not mark complete.
    client = _initiator()
    client.step()

    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
    ).pack()
    client.step(request_mic)

    forged_complete = sp.NegTokenResp(
        neg_state=sp.NegState.accept_complete,
        response_token=b"MECH-REPLY",
    ).pack()
    with pytest.raises(InvalidTokenError, match="without the required mechListMIC"):
        client.step(forged_complete)

    _assert_not_usable(client)


def test_legacy_blanked_mic_is_not_a_verification_bypass():
    # Old implementations send mechListMIC == responseToken which NegotiateProxy blanks out for compatibility.
    # That quirk must not be usable as a free pass when a MIC exchange is active.
    client = _initiator()
    client.step()

    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
    ).pack()
    client.step(request_mic)

    arbitrary = b"ARBITRARY-RESPONSE-TOKEN-USED-AS-MIC"
    legacy_complete = sp.NegTokenResp(
        neg_state=sp.NegState.accept_complete,
        response_token=arbitrary,
        mech_list_mic=arbitrary,  # Blank-ed by the compatibility check, so no MIC is actually verified.
    ).pack()
    with pytest.raises(InvalidTokenError, match="without the required mechListMIC"):
        client.step(legacy_complete)

    _assert_not_usable(client)


def test_legacy_blanked_mic_without_mic_exchange_still_completes():
    # When no MIC exchange was ever started the legacy blanking branch must still allow a normal completion, proving
    # the branch itself is not treated as evidence either way - only an active MIC requirement makes the MIC mandatory.
    client = _initiator()
    client.step()

    arbitrary = b"ARBITRARY-RESPONSE-TOKEN-USED-AS-MIC"
    legacy_complete = sp.NegTokenResp(
        neg_state=sp.NegState.accept_complete,
        supported_mech=GSSMech.kerberos.value,
        response_token=arbitrary,
        mech_list_mic=arbitrary,
    ).pack()
    assert client.step(legacy_complete) is None
    assert client.complete is True
    assert client._mic_recv is False
    _assert_usable(client)


@pytest.mark.parametrize(
    "alias_oid",
    [GSSMech._ms_kerberos.value, GSSMech._kerberos_draft.value],
)
def test_legal_oid_alias_completes_without_forced_mic(alias_oid):
    # A legal Kerberos OID alias selected as the preferred mech needs no MIC exchange and still completes normally.
    client = _initiator()
    client.step()

    accept_complete = sp.NegTokenResp(
        neg_state=sp.NegState.accept_complete,
        supported_mech=alias_oid,
        response_token=b"MECH-REPLY",
    ).pack()
    assert client.step(accept_complete) is None
    assert client.complete is True
    assert client.negotiated_protocol == "kerberos"
    assert client._mic_requested is False
    _assert_usable(client)


def test_acceptor_reselection_triggers_and_verifies_mic(monkeypatch):
    # When the acceptor's preferred mech differs from the initiator's first choice it must enter the MIC path. The
    # host prefers Kerberos but this acceptor only holds an NTLM context, and the initiator offers NTLM first - so the
    # acceptor's preference (Kerberos) cannot match the offered first choice and request-mic becomes mandatory.
    monkeypatch.setattr(
        NegotiateProxy,
        "available_protocols",
        classmethod(lambda cls, options=None: ["kerberos", "ntlm", "negotiate"]),
    )

    initiator_mechs = [GSSMech.ntlm.value, GSSMech.kerberos.value]

    def _make_acceptor() -> NegotiateProxy:
        return NegotiateProxy(
            usage="accept",
            options=spnego.NegotiateOptions.use_negotiate,
            _negotiate_contexts={GSSMech.ntlm: FakeMechContext("accept")},
        )

    acceptor = _make_acceptor()
    init_token = sp.NegTokenInit(mech_types=initiator_mechs, mech_token=b"MECH-REQUEST").pack()
    first_reply = _unpack(acceptor.step(init_token))

    # The acceptor re-selected NTLM (its only usable mech) and must request a MIC while echoing an offered OID.
    assert isinstance(first_reply, sp.NegTokenResp)
    assert first_reply.neg_state == sp.NegState.request_mic
    assert first_reply.supported_mech == GSSMech.ntlm.value
    assert acceptor._mic_required is True
    # The acceptor confirms the exact list and order the initiator sent.
    assert acceptor._mech_list == initiator_mechs

    # A MIC over a reordered (or tampered) list must fail verification and leave the context unusable.
    reordered = [GSSMech.kerberos.value, GSSMech.ntlm.value]
    bad_acceptor = _make_acceptor()
    bad_acceptor.step(sp.NegTokenInit(mech_types=initiator_mechs, mech_token=b"MECH-REQUEST").pack())
    with pytest.raises(InvalidTokenError, match="mechListMIC verification failed"):
        bad_acceptor.step(sp.NegTokenResp(mech_list_mic=_mech_list_mic(reordered)).pack())
    _assert_not_usable(bad_acceptor)

    # The same acceptor completes when the MIC matches the original list order.
    good_acceptor = _make_acceptor()
    good_acceptor.step(sp.NegTokenInit(mech_types=initiator_mechs, mech_token=b"MECH-REQUEST").pack())
    good_acceptor.step(sp.NegTokenResp(mech_list_mic=_mech_list_mic(initiator_mechs)).pack())
    assert good_acceptor.complete is True
    _assert_usable(good_acceptor)


def test_reordered_mech_list_mic_mismatch_is_rejected_on_initiator():
    # The initiator stores the exact list it offered; a MIC computed over a reordered copy fails verification.
    client = _initiator()
    offered = _unpack(client.step()).mech_types
    reordered = list(reversed(offered)) if len(offered) > 1 else [GSSMech.ntlm.value] + offered

    request_mic = sp.NegTokenResp(
        neg_state=sp.NegState.request_mic,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
        mech_list_mic=_mech_list_mic(reordered),
    ).pack()
    with pytest.raises(InvalidTokenError, match="mechListMIC verification failed"):
        client.step(request_mic)
    _assert_not_usable(client)


def test_dce_style_always_requires_mic():
    # DCE style authentication forces the mechListMIC even for Kerberos.
    client = NegotiateProxy(
        context_req=ContextReq.dce_style,
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeMechContext("initiate")},
    )
    offered = _unpack(client.step()).mech_types

    # An accept-complete without MIC is rejected even though request-mic was never explicitly exchanged.
    accept_complete = sp.NegTokenResp(
        neg_state=sp.NegState.accept_complete,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"MECH-REPLY",
    ).pack()
    with pytest.raises(InvalidTokenError, match="without the required mechListMIC"):
        client.step(accept_complete)
    _assert_not_usable(client)

    # Providing a MIC over the confirmed list lets the exchange finish.
    good_client = NegotiateProxy(
        context_req=ContextReq.dce_style,
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeMechContext("initiate")},
    )
    good_offered = _unpack(good_client.step()).mech_types
    good_client.step(
        sp.NegTokenResp(
            neg_state=sp.NegState.accept_complete,
            supported_mech=GSSMech.kerberos.value,
            response_token=b"MECH-REPLY",
            mech_list_mic=_mech_list_mic(good_offered),
        ).pack()
    )
    assert good_client.complete is True
    _assert_usable(good_client)


# ---------------------------------------------------------------------------
# Pure NTLM end-to-end SPNEGO exchange with the real Python NTLM provider.
# These exercise the production NTLM mechListMIC sign/verify rather than a fake.
# ---------------------------------------------------------------------------


def _ntlm_spnego_pair(ntlm_cred):
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
    )
    server = spnego.server(protocol="negotiate")
    return client, server


def _ntlm_final_acceptor_token(ntlm_cred):
    """Run the standard NTLM SPNEGO legs and return the initiator plus its final acceptor NegTokenResp token."""
    client, server = _ntlm_spnego_pair(ntlm_cred)
    negotiate = client.step()
    challenge = server.step(negotiate)
    authenticate = client.step(challenge)
    final_token = server.step(authenticate)
    return client, final_token


def test_ntlm_spnego_happy_path_keeps_original_step_count(ntlm_cred):
    # The non-downgraded NTLM SPNEGO exchange must still complete in the same number of legs as before the fix.
    client, server = _ntlm_spnego_pair(ntlm_cred)

    negotiate = client.step()
    assert negotiate is not None and not client.complete and not server.complete

    challenge = server.step(negotiate)
    assert challenge is not None and not client.complete and not server.complete

    authenticate = client.step(challenge)
    assert authenticate is not None and not client.complete and not server.complete

    # The acceptor finishes the inner NTLM auth and emits its mechListMIC in the same response.
    mech_list_mic_token = server.step(authenticate)
    assert mech_list_mic_token is not None
    assert server.complete is True
    assert client.complete is False

    final = client.step(mech_list_mic_token)
    assert final is None
    assert client.complete is True
    assert server.complete is True
    assert client.negotiated_protocol == "ntlm"

    # Per-message protection works on both sides after the verified MIC exchange.
    wrapped = client.wrap(b"ntlm secret")
    assert server.unwrap(wrapped.data).data == b"ntlm secret"


def test_ntlm_spnego_missing_mechlistmic_rejected(ntlm_cred):
    client, final_token = _ntlm_final_acceptor_token(ntlm_cred)

    response = sp.unpack_token(final_token)
    assert response.mech_list_mic is not None  # NTLM normally carries a MIC here.

    stripped = sp.NegTokenResp(
        neg_state=response.neg_state,
        supported_mech=response.supported_mech,
        response_token=response.response_token,
    ).pack()

    with pytest.raises(InvalidTokenError, match="without the required mechListMIC"):
        client.step(stripped)

    assert client.complete is False
    with pytest.raises(NoContextError):
        client.wrap(b"should fail")


def test_ntlm_spnego_bad_mechlistmic_rejected(ntlm_cred):
    client, final_token = _ntlm_final_acceptor_token(ntlm_cred)
    response = sp.unpack_token(final_token)

    corrupted = sp.NegTokenResp(
        neg_state=response.neg_state,
        supported_mech=response.supported_mech,
        response_token=response.response_token,
        mech_list_mic=b"\x01" * len(response.mech_list_mic),
    ).pack()

    with pytest.raises(BadMICError):
        client.step(corrupted)

    assert client.complete is False
    with pytest.raises(NoContextError):
        client.wrap(b"should fail")
