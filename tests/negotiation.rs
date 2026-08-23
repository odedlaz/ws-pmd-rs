//! The RFC 7692 negotiation matrix, driven through the public API only.
#![expect(clippy::expect_used, clippy::unwrap_used, reason = "a panic is how a test reports")]

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use permessage_deflate::{
    ClientConfig, ClientHandshake, ClientOffer, ConfigError, Negotiated, NegotiationError,
    PmdComposition, ServerConfig, ServerHandshake,
};

fn headers(values: &[&[u8]]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for value in values {
        map.append(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_bytes(value).expect("test input is a valid header value"),
        );
    }
    map
}

/// Drive a client from a config through a response, skipping the seal by
/// sealing against the request the offer itself installed.
fn client_round_trip(
    config: ClientConfig,
    response: &[&[u8]],
) -> Result<Option<Negotiated>, NegotiationError> {
    client_round_trip_composing(config, response, PmdComposition::Compatible)
}

fn client_round_trip_composing(
    config: ClientConfig,
    response: &[&[u8]],
    composition: PmdComposition,
) -> Result<Option<Negotiated>, NegotiationError> {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(config, &mut request).expect("a fresh map has no offer");
    offer.seal(&request)?.finish(&headers(response), composition)
}

fn offer_value(config: ClientConfig) -> String {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(config, &mut request).expect("a fresh map has no offer");
    offer.value().to_str().expect("the offer is ASCII").to_owned()
}

// ---------------------------------------------------------------- validate-parser

#[test]
fn accepts_a_quoted_window_value() {
    let agreed = client_round_trip(
        ClientConfig::new(),
        &[br#"permessage-deflate; server_max_window_bits="12""#],
    )
    .expect("quoted values are legal")
    .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 12);
}

#[test]
fn resolves_a_quoted_pair_inside_a_window_value() {
    // `"1\2"` is the quoted-pair spelling of `12`.
    let agreed = client_round_trip(
        ClientConfig::new(),
        &[br#"permessage-deflate; server_max_window_bits="1\2""#],
    )
    .expect("quoted pairs are legal")
    .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 12);
}

/// A quoted comma can no longer produce a *selection* under any behaviour: the
/// value unescapes to something with commas and spaces in it, which is not a
/// `token`, so the field is malformed however it was split. What this row still
/// holds is that the answer is the error and never the selection inside the
/// quotes that the peer never made.
#[test]
fn a_quoted_comma_never_manufactures_a_selection() {
    let error = client_round_trip(
        ClientConfig::new(),
        &[br#"x-other; note="a, permessage-deflate; server_max_window_bits=9""#],
    )
    .expect_err("the unescaped value is not a token");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

/// Isolation is about not *interpreting* an unrelated extension, not about
/// accepting bad syntax from one. RFC 6455 section 9.1's MUST attaches to any
/// non-conforming received value, and `token` admits no byte above 127, so a
/// conforming `permessage-deflate` beside it does not rescue the field.
#[test]
fn an_unrelated_extension_carrying_non_token_bytes_is_malformed() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"x-binary; tag=\xff\xfe, permessage-deflate"])
            .expect_err("0xff is not a token character");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

#[test]
fn an_unrelated_extension_may_use_every_token_character() {
    // The guard against over-rejection, which is the failure direction a new
    // validator actually has. Every byte here is `tchar`, so a validator that
    // is even slightly too narrow fails a conforming field.
    let agreed = client_round_trip(
        ClientConfig::new(),
        &[br"x-!#$%&'*+-.^_`|~; weird=1, permessage-deflate"],
    )
    .expect("every one of these bytes is a token character")
    .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 15);
}

/// `exact-tokens`: RFC 6455 defines *ASCII case-insensitive* and applies it
/// where it means it, never to these tokens; RFC 7692 has no case language at
/// all. So a mixed-case spelling is conforming `token` syntax naming an
/// extension nobody registered -- `Ok(None)`, never `MalformedHeader`.
#[test]
fn a_mixed_case_extension_name_is_valid_syntax_and_is_not_this_extension() {
    let selected = client_round_trip(
        ClientConfig::new(),
        &[b"PerMessage-DEFLATE; Server_No_Context_Takeover"],
    )
    .expect("mixed case is a conforming token");
    assert!(selected.is_none(), "an unregistered spelling is not a selection");
}

#[test]
fn a_mixed_case_parameter_name_is_unknown_rather_than_malformed() {
    let error = client_round_trip(
        ClientConfig::new(),
        &[b"permessage-deflate; Server_No_Context_Takeover"],
    )
    .expect_err("the extension is this one; the parameter is not a registered one");
    assert_eq!(error, NegotiationError::UnknownParameter);
}

#[test]
fn a_mixed_case_parameter_declines_that_alternative_and_keeps_the_next() {
    let (proposed, _) = server_select(
        ServerConfig::new(),
        &[b"permessage-deflate; Server_No_Context_Takeover, \
            permessage-deflate; server_no_context_takeover"],
    )
    .expect("the second alternative spells it as registered");
    assert_eq!(proposed, "permessage-deflate; server_no_context_takeover");
}

#[test]
fn a_duplicate_parameter_is_rejected() {
    let error = client_round_trip(
        ClientConfig::new(),
        &[b"permessage-deflate; server_max_window_bits=12; server_max_window_bits=12"],
    )
    .expect_err("a repeated parameter is ambiguous");
    assert_eq!(error, NegotiationError::DuplicateParameter);
}

/// `strict-parser`, settled 2026-08-23: a value whose quoting never closes has
/// no determinable element boundaries, so it errors rather than being answered.
#[test]
fn an_unterminated_quote_errors_rather_than_classifying() {
    let error = client_round_trip(ClientConfig::new(), &[br#"permessage-deflate; x="open"#])
        .expect_err("the element boundaries are unknowable");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

#[test]
fn a_trailing_escape_errors() {
    let error = client_round_trip(ClientConfig::new(), &[br#"permessage-deflate; x="a\"#])
        .expect_err("the escape has nothing to escape");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

#[test]
fn an_unterminated_quote_fails_the_server_rather_than_declining() {
    // Two inputs because two mutants reach a selection by different routes. If
    // quotes stop delimiting, the hidden comma splits and the second
    // alternative becomes selectable. If quotes still delimit but the imbalance
    // stops being an error, the first alternative does.
    for offer in [
        br#"permessage-deflate; x="open, permessage-deflate"#.as_slice(),
        br#"permessage-deflate, x-other; note="oops"#.as_slice(),
    ] {
        let error = ServerHandshake::accept(ServerConfig::new(), &headers(&[offer]))
            .expect_err("the element boundaries are unknowable");
        assert_eq!(error, NegotiationError::MalformedHeader, "{}", String::from_utf8_lossy(offer));
    }
}

#[test]
fn a_leading_zero_window_is_rejected() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; server_max_window_bits=09"])
            .expect_err("09 is not a wire form RFC 7692 defines");
    assert_eq!(error, NegotiationError::InvalidWindowBits);
}

#[test]
fn an_unknown_parameter_fails_the_client() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; nonstandard_option=1"])
            .expect_err("an unrecognised parameter cannot be agreed to");
    assert_eq!(error, NegotiationError::UnknownParameter);
}

#[test]
fn a_flag_parameter_may_not_carry_a_value() {
    let error = client_round_trip(
        ClientConfig::new(),
        &[b"permessage-deflate; server_no_context_takeover=1"],
    )
    .expect_err("the takeover parameters are valueless");
    assert_eq!(error, NegotiationError::ParameterArity);
}

/// `whole-list-first`. A single pass that validates as it selects passes this
/// row: it takes the conforming first element and returns before it ever reads
/// the second. Two passes are what the RFC asks for, and this is the row that
/// tells them apart -- on one line, and again across two, because RFC 7230
/// combines separate field lines into one list.
#[test]
fn a_malformed_element_after_a_valid_selection_still_fails_the_field() {
    let one_line =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate, x-other; tag=\xff"])
            .expect_err("a selectable first element does not excuse the second");
    assert_eq!(one_line, NegotiationError::MalformedHeader);

    let two_lines =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate", b"x-other; tag=\xff"])
            .expect_err("separate field lines are still one list");
    assert_eq!(two_lines, NegotiationError::MalformedHeader);
}

#[test]
fn the_server_reads_the_whole_field_before_selecting() {
    let one_line = ServerHandshake::accept(
        ServerConfig::new(),
        &headers(&[b"permessage-deflate, x-other; tag=\xff"]),
    )
    .expect_err("a supportable first offer does not excuse the second element");
    assert_eq!(one_line, NegotiationError::MalformedHeader);

    let two_lines = ServerHandshake::accept(
        ServerConfig::new(),
        &headers(&[b"permessage-deflate", b"x-other; tag=\xff"]),
    )
    .expect_err("separate field lines are still one list");
    assert_eq!(two_lines, NegotiationError::MalformedHeader);
}

/// `extension-list = 1#extension`. The list rule permits empty positions but
/// not a list made only of them, so this is not the same as an absent header --
/// which is the distinction the matrix could not make before.
#[test]
fn a_present_but_empty_field_is_malformed_not_absent() {
    for value in [&b""[..], b" ", b" , "] {
        let client = client_round_trip(ClientConfig::new(), &[value])
            .expect_err("a present field with no element is a list with no members");
        assert_eq!(client, NegotiationError::MalformedHeader, "{value:?}");

        let server = ServerHandshake::accept(ServerConfig::new(), &headers(&[value]))
            .expect_err("a present field with no element is a list with no members");
        assert_eq!(server, NegotiationError::MalformedHeader, "{value:?}");
    }

    assert!(client_round_trip(ClientConfig::new(), &[])
        .expect("an absent header is not a malformed one")
        .is_none());
    assert!(ServerHandshake::accept(ServerConfig::new(), &headers(&[]))
        .expect("an absent header is not a malformed one")
        .is_none());
}

#[test]
fn an_empty_list_position_beside_a_real_element_is_legal() {
    let agreed = client_round_trip(ClientConfig::new(), &[b", permessage-deflate, "])
        .expect("RFC 7230 list rules permit empty positions")
        .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 15);
}

/// RFC 6455 section 9.1: "the value after quoted-string unescaping MUST conform
/// to the 'token' ABNF". The quoted spelling buys a different wire encoding,
/// not a different alphabet -- and the field fails as syntax before anything
/// tries to read `1 2` as a width.
#[test]
fn a_quoted_value_that_unescapes_to_a_non_token_is_malformed() {
    let error = client_round_trip(
        ClientConfig::new(),
        &[br#"permessage-deflate; server_max_window_bits="1 2""#],
    )
    .expect_err("a space is not a token character");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

/// `extension-param = token [ "=" ... ]`, so an absent parameter name is a
/// grammar break, not a parameter this crate happens not to know.
#[test]
fn an_empty_parameter_name_is_malformed_not_unknown() {
    for offer in [&b"permessage-deflate;"[..], b"permessage-deflate; =1"] {
        let error = client_round_trip(ClientConfig::new(), &[offer])
            .expect_err("there is no name here to be unknown");
        assert_eq!(error, NegotiationError::MalformedHeader, "{}", String::from_utf8_lossy(offer));
    }
}

// --------------------------------------------------------- validate-client-matrix

#[test]
fn the_default_offer_advertises_a_valueless_client_window() {
    assert_eq!(offer_value(ClientConfig::new()), "permessage-deflate; client_max_window_bits");
}

#[test]
fn a_bounded_offer_states_both_widths() {
    let config = ClientConfig::new()
        .server_no_context_takeover(true)
        .client_no_context_takeover(true)
        .server_max_window_bits(10)
        .expect("10 is a legal peer bound")
        .client_max_window_bits(11)
        .expect("11 is a legal local bound");
    assert_eq!(
        offer_value(config),
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; \
         server_max_window_bits=10; client_max_window_bits=11"
    );
}

#[test]
fn a_declining_response_is_not_an_error() {
    assert!(client_round_trip(ClientConfig::new(), &[b"x-other"])
        .expect("no PMD is legal")
        .is_none());
    assert!(client_round_trip(ClientConfig::new(), &[]).expect("no header is legal").is_none());
}

#[test]
fn omitted_optional_parameters_agree_to_the_offered_bounds() {
    let config = ClientConfig::new().client_max_window_bits(11).expect("legal");
    let agreed = client_round_trip(config, &[b"permessage-deflate"])
        .expect("a bare selection is legal")
        .expect("the server selected it");
    assert!(!agreed.local_no_context_takeover());
    assert!(!agreed.peer_no_context_takeover());
    assert_eq!(agreed.peer_max_window_bits(), 15);
    // Unanswered means unconstrained by the server, so this side still holds
    // itself to the width it advertised.
    assert_eq!(agreed.local_max_window_bits(), 11);
}

/// The historical `|=`-to-`=` mutant: a server may impose a takeover limit the
/// client never volunteered, and the agreement must be the union.
#[test]
fn a_server_may_impose_client_no_context_takeover() {
    let agreed = client_round_trip(
        ClientConfig::new(),
        &[b"permessage-deflate; client_no_context_takeover"],
    )
    .expect("a stronger response is legal")
    .expect("the server selected it");
    assert!(agreed.local_no_context_takeover());
}

#[test]
fn an_offered_client_takeover_survives_a_silent_response() {
    let config = ClientConfig::new().client_no_context_takeover(true);
    let agreed = client_round_trip(config, &[b"permessage-deflate"])
        .expect("legal")
        .expect("the server selected it");
    assert!(agreed.local_no_context_takeover());
}

#[test]
fn a_required_server_takeover_must_be_confirmed() {
    let config = ClientConfig::new().server_no_context_takeover(true);
    let error = client_round_trip(config, &[b"permessage-deflate"])
        .expect_err("the requirement was not echoed");
    assert_eq!(error, NegotiationError::ServerTakeoverNotHonoured);
}

#[test]
fn a_bounded_server_window_must_be_confirmed() {
    let config = ClientConfig::new().server_max_window_bits(10).expect("legal");
    let error =
        client_round_trip(config, &[b"permessage-deflate"]).expect_err("the bound was not echoed");
    assert_eq!(error, NegotiationError::ServerWindowUnconfirmed);
}

#[test]
fn a_widened_server_window_is_rejected() {
    let config = ClientConfig::new().server_max_window_bits(10).expect("legal");
    let error = client_round_trip(config, &[b"permessage-deflate; server_max_window_bits=12"])
        .expect_err("12 exceeds the offered 10");
    assert_eq!(error, NegotiationError::ServerWindowTooLarge);
}

/// RFC 7692 section 7.1.2.2: the offered value is a hint the server may ignore
/// or answer wider, so failing here would reject a conforming peer. Section
/// 7.2.1 would then permit compressing up to the agreed value; installing the
/// offer instead is local policy, because the offer came from a configured
/// bound and a peer allowing more does not erase a setting.
#[test]
fn a_response_wider_than_the_client_hint_narrows_to_the_hint() {
    let config = ClientConfig::new().client_max_window_bits(10).expect("legal");
    let agreed = client_round_trip(config, &[b"permessage-deflate; client_max_window_bits=12"])
        .expect("a wider answer is conforming")
        .expect("the server selected it");
    assert_eq!(agreed.local_max_window_bits(), 10);
}

#[test]
fn a_response_narrower_than_the_client_hint_is_installed_as_sent() {
    let config = ClientConfig::new().client_max_window_bits(12).expect("legal");
    let agreed = client_round_trip(config, &[b"permessage-deflate; client_max_window_bits=10"])
        .expect("a narrower answer is conforming")
        .expect("the server selected it");
    assert_eq!(agreed.local_max_window_bits(), 10);
}

#[test]
fn a_client_window_below_the_buildable_floor_is_rejected() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; client_max_window_bits=8"])
            .expect_err("no local compressor can be built at 8");
    assert_eq!(error, NegotiationError::ClientWindowTooNarrow);
}

#[test]
fn a_valueless_server_window_in_a_response_is_rejected() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; server_max_window_bits"])
            .expect_err("server_max_window_bits carries a width or it says nothing");
    assert_eq!(error, NegotiationError::ParameterArity);
}

#[test]
fn a_valueless_client_window_in_a_response_is_rejected() {
    let error =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; client_max_window_bits"])
            .expect_err("a response must state the chosen width");
    assert_eq!(error, NegotiationError::ClientWindowValueless);
}

/// Every other bounded-offer row is a rejection, so an over-rejecting mutant
/// passes all of them. This is the row that says the conforming response is
/// accepted and that each answered value reaches the agreement.
#[test]
fn a_bounded_offer_accepts_the_response_that_answers_it() {
    let config = ClientConfig::new()
        .server_no_context_takeover(true)
        .server_max_window_bits(10)
        .expect("10 is a legal peer bound")
        .client_max_window_bits(11)
        .expect("11 is a legal local bound");
    let agreed = client_round_trip(
        config,
        &[b"permessage-deflate; server_no_context_takeover; server_max_window_bits=10; \
            client_max_window_bits=11"],
    )
    .expect("the response answers every offered bound")
    .expect("the server selected it");
    assert!(agreed.peer_no_context_takeover());
    assert_eq!(agreed.peer_max_window_bits(), 10);
    assert_eq!(agreed.local_max_window_bits(), 11);
}

#[test]
fn a_response_may_narrow_below_the_offered_bound() {
    let config = ClientConfig::new().server_max_window_bits(10).expect("legal");
    let agreed = client_round_trip(config, &[b"permessage-deflate; server_max_window_bits=9"])
        .expect("narrower than offered is inside the offer")
        .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 9);
}

#[test]
fn a_peer_window_of_eight_is_kept_as_eight() {
    let agreed =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate; server_max_window_bits=8"])
            .expect("8 is legal for the peer's compressor")
            .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 8);
}

#[test]
fn two_selections_are_rejected_across_one_line_and_across_two() {
    let one_line =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate, permessage-deflate"])
            .expect_err("one selection only");
    assert_eq!(one_line, NegotiationError::DuplicateExtension);

    let two_lines =
        client_round_trip(ClientConfig::new(), &[b"permessage-deflate", b"permessage-deflate"])
            .expect_err("separate field lines are still one list");
    assert_eq!(two_lines, NegotiationError::DuplicateExtension);
}

#[test]
fn a_selection_is_found_on_a_later_header_line() {
    let agreed = client_round_trip(ClientConfig::new(), &[b"x-other", b"permessage-deflate"])
        .expect("legal")
        .expect("the server selected it");
    assert_eq!(agreed.peer_max_window_bits(), 15);
}

// ------------------------------------------------------------------ the seal

#[test]
fn installing_over_a_caller_owned_offer_is_a_collision() {
    let mut request = headers(&[b"permessage-deflate"]);
    let error = ClientOffer::install(ClientConfig::new(), &mut request)
        .expect_err("two owners of one extension");
    assert_eq!(error, NegotiationError::OfferCollision);
}

#[test]
fn sealing_detects_removal_replacement_and_duplication() {
    for (name, final_request) in [
        ("removed", headers(&[])),
        ("replaced", headers(&[b"permessage-deflate; server_max_window_bits=9"])),
        // The exact installed value twice is what isolates multiplicity: the
        // byte-equality guard passes both elements, so only the count guard can
        // reject it. A second element that differs never reaches the count.
        (
            "duplicated exactly",
            headers(&[
                b"permessage-deflate; client_max_window_bits",
                b"permessage-deflate; client_max_window_bits",
            ]),
        ),
        (
            "duplicated and rewritten",
            headers(&[b"permessage-deflate; client_max_window_bits", b"permessage-deflate"]),
        ),
    ] {
        let mut request = HeaderMap::new();
        let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("fresh");
        let error = offer.seal(&final_request).expect_err(name);
        assert_eq!(error, NegotiationError::OfferAltered, "{name}");
    }
}

#[test]
fn sealing_accepts_the_offer_beside_an_unrelated_extension() {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("fresh");
    request.append(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("x-other; a=1"));
    offer.seal(&request).expect("an unrelated extension does not disturb the offer");
}

// ----------------------------------------------------- the no-offer workflow

/// RFC 7692 section 7.1: a server may select only from what the client offered.
/// A client that offered nothing is the only side that can catch a selection
/// anyway, and before `seal_without_offer` the crate had no state for it -- the
/// rule fell to every host separately.
#[test]
fn a_selection_against_no_offer_is_unsolicited() {
    let error = ClientHandshake::seal_without_offer(&headers(&[b"x-other"]))
        .expect("the request carries no offer")
        .finish(&headers(&[b"permessage-deflate"]), PmdComposition::Compatible)
        .expect_err("the server selected what was never offered");
    assert_eq!(error, NegotiationError::UnsolicitedExtension);
}

#[test]
fn no_offer_and_no_selection_is_an_ordinary_declined_connection() {
    for response in [&[b"x-other" as &[u8]] as &[&[u8]], &[]] {
        let agreed = ClientHandshake::seal_without_offer(&headers(&[]))
            .expect("the request carries no offer")
            .finish(&headers(response), PmdComposition::Compatible)
            .expect("no selection is a normal outcome");
        assert!(agreed.is_none());
    }
}

/// The peer breaking the protocol outranks the host's account of its own
/// extension set, matching the server side, where a rewritten response outranks
/// a conflict. Without this row the conflict arm could widen to both states.
#[test]
fn an_unsolicited_selection_outranks_a_composition_conflict() {
    let error = ClientHandshake::seal_without_offer(&headers(&[]))
        .expect("the request carries no offer")
        .finish(&headers(&[b"permessage-deflate"]), PmdComposition::Conflict)
        .expect_err("both faults are present");
    assert_eq!(error, NegotiationError::UnsolicitedExtension);
}

#[test]
fn sealing_without_an_offer_rejects_a_request_that_has_one() {
    let error = ClientHandshake::seal_without_offer(&headers(&[b"permessage-deflate"]))
        .expect_err("this is the wrong state for these headers");
    assert_eq!(error, NegotiationError::OfferCollision);
}

#[test]
fn the_no_offer_path_still_reads_the_response_grammar() {
    let error = ClientHandshake::seal_without_offer(&headers(&[]))
        .expect("the request carries no offer")
        .finish(&headers(&[br#"x-other; note="open"#]), PmdComposition::Compatible)
        .expect_err("the element boundaries are unknowable");
    assert_eq!(error, NegotiationError::MalformedHeader);
}

#[test]
fn only_a_sealed_offer_reports_a_value() {
    assert!(ClientHandshake::seal_without_offer(&headers(&[]))
        .expect("no offer")
        .value()
        .is_none());

    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("fresh");
    let sealed = offer.seal(&request).expect("unchanged");
    assert_eq!(
        sealed.value().expect("an offered handshake reports it"),
        "permessage-deflate; client_max_window_bits"
    );
}

// --------------------------------------------------------- validate-server-matrix

fn server_select(config: ServerConfig, request: &[&[u8]]) -> Option<(String, Negotiated)> {
    let handshake = ServerHandshake::accept(config, &headers(request))
        .expect("this helper is for requests whose syntax is conforming")?;
    let proposed = handshake.value().to_str().expect("ASCII").to_owned();
    let response = headers(&[proposed.as_bytes()]);
    let agreed =
        handshake.finish(&response, PmdComposition::Compatible).expect("the proposal is unchanged");
    Some((proposed, agreed.expect("the proposal selected it")))
}

/// Two supportable alternatives, so first-acceptable and last-acceptable
/// disagree here. The skip-unsupported row below cannot tell them apart: its
/// only acceptable alternative is the last one either rule would reach.
#[test]
fn the_server_takes_the_first_acceptable_alternative() {
    let (proposed, agreed) = server_select(
        ServerConfig::new(),
        &[b"permessage-deflate; server_max_window_bits=12, \
            permessage-deflate; server_max_window_bits=10"],
    )
    .expect("both alternatives are supportable");
    assert_eq!(proposed, "permessage-deflate; server_max_window_bits=12");
    assert_eq!(agreed.local_max_window_bits(), 12);
}

#[test]
fn the_server_skips_an_unsupportable_alternative() {
    // The first demands an 8-bit server compressor, which cannot be built.
    let (proposed, agreed) = server_select(
        ServerConfig::new(),
        &[b"permessage-deflate; server_max_window_bits=8, \
            permessage-deflate; server_max_window_bits=12"],
    )
    .expect("the second alternative is supportable");
    assert_eq!(proposed, "permessage-deflate; server_max_window_bits=12");
    assert_eq!(agreed.local_max_window_bits(), 12);
}

#[test]
fn the_server_declines_a_local_window_of_eight() {
    assert!(server_select(ServerConfig::new(), &[b"permessage-deflate; server_max_window_bits=8"])
        .is_none());
}

#[test]
fn the_server_accepts_a_peer_window_of_eight() {
    let (proposed, agreed) =
        server_select(ServerConfig::new(), &[b"permessage-deflate; client_max_window_bits=8"])
            .expect("8 is legal for the peer's compressor");
    assert_eq!(proposed, "permessage-deflate; client_max_window_bits=8");
    assert_eq!(agreed.peer_max_window_bits(), 8);
}

#[test]
fn the_server_declines_an_unknown_parameter_and_takes_the_next() {
    // The unknown parameter sits beside a supported one, so dropping it and
    // accepting this alternative renders `server_max_window_bits=12` while
    // declining it renders bare. Two bare alternatives render the same bytes.
    let (proposed, _) = server_select(
        ServerConfig::new(),
        &[b"permessage-deflate; nonstandard=1; server_max_window_bits=12, \
            permessage-deflate"],
    )
    .expect("the second alternative is clean");
    assert_eq!(proposed, "permessage-deflate");
}

#[test]
fn a_sole_unknown_parameter_leaves_the_server_nothing_to_select() {
    assert!(server_select(ServerConfig::new(), &[b"permessage-deflate; nonstandard=1"]).is_none());
}

#[test]
fn the_server_declines_a_valueless_server_window_and_takes_the_next() {
    // `ParameterArity` has two constructor paths — a valued takeover flag and a
    // valueless `server_max_window_bits`. This is the second one, on the path
    // where an arity break declines one alternative rather than failing.
    let (proposed, _) = server_select(
        ServerConfig::new(),
        &[b"permessage-deflate; server_max_window_bits; client_no_context_takeover, \
            permessage-deflate"],
    )
    .expect("the second alternative is clean");
    assert_eq!(proposed, "permessage-deflate");
}

#[test]
fn the_server_declines_a_request_with_no_offer() {
    assert!(server_select(ServerConfig::new(), &[b"x-other"]).is_none());
    assert!(server_select(ServerConfig::new(), &[]).is_none());
}

#[test]
fn the_server_cannot_bound_a_client_window_the_offer_never_invited() {
    let config = ServerConfig::new().client_max_window_bits(10).expect("legal");
    assert!(server_select(config, &[b"permessage-deflate"]).is_none());
}

#[test]
fn a_valueless_client_window_lets_the_server_choose() {
    let config = ServerConfig::new().client_max_window_bits(10).expect("legal");
    let (proposed, agreed) =
        server_select(config, &[b"permessage-deflate; client_max_window_bits"])
            .expect("the offer invited a bound");
    assert_eq!(proposed, "permessage-deflate; client_max_window_bits=10");
    assert_eq!(agreed.peer_max_window_bits(), 10);
}

#[test]
fn the_server_echoes_an_offered_server_takeover() {
    let (proposed, agreed) =
        server_select(ServerConfig::new(), &[b"permessage-deflate; server_no_context_takeover"])
            .expect("the offer is supportable as written");
    assert_eq!(proposed, "permessage-deflate; server_no_context_takeover");
    assert!(agreed.local_no_context_takeover());
}

/// Configured policy has to reach two places, and a mutant can drop either one
/// while the other still looks right: the header the peer reads, and the
/// agreement this side runs its own compressor from.
#[test]
fn a_server_window_policy_reaches_the_response_and_the_agreement() {
    let config = ServerConfig::new()
        .server_no_context_takeover(true)
        .server_max_window_bits(12)
        .expect("12 is a legal local bound");
    let (proposed, agreed) = server_select(config, &[b"permessage-deflate"])
        .expect("a bare offer accepts any narrowing the server imposes");
    assert_eq!(
        proposed,
        "permessage-deflate; server_no_context_takeover; server_max_window_bits=12"
    );
    assert!(agreed.local_no_context_takeover());
    assert_eq!(agreed.local_max_window_bits(), 12);
}

#[test]
fn the_server_imposes_its_own_takeover_policy() {
    let config = ServerConfig::new().client_no_context_takeover(true);
    let (proposed, agreed) = server_select(config, &[b"permessage-deflate"]).expect("legal");
    assert_eq!(proposed, "permessage-deflate; client_no_context_takeover");
    assert!(agreed.peer_no_context_takeover());
}

#[test]
fn a_removed_response_extension_yields_no_agreement() {
    let handshake =
        ServerHandshake::accept(ServerConfig::new(), &headers(&[b"permessage-deflate"]))
            .expect("the request is conforming")
            .expect("selected");
    assert!(handshake
        .finish(&headers(&[]), PmdComposition::Compatible)
        .expect("removal is allowed")
        .is_none());
}

#[test]
fn a_rewritten_response_is_rejected_even_when_the_offers_permit_it() {
    // Both widths are supportable against this offer; the server proposed 15.
    let handshake = ServerHandshake::accept(
        ServerConfig::new(),
        &headers(&[b"permessage-deflate; client_max_window_bits"]),
    )
    .expect("the request is conforming")
    .expect("selected");
    let error = handshake
        .finish(
            &headers(&[b"permessage-deflate; client_max_window_bits=10"]),
            PmdComposition::Compatible,
        )
        .expect_err("the header and the runtime state commit together");
    assert_eq!(error, NegotiationError::ResponseAltered);
}

#[test]
fn a_duplicated_response_extension_is_rejected() {
    let handshake =
        ServerHandshake::accept(ServerConfig::new(), &headers(&[b"permessage-deflate"]))
            .expect("the request is conforming")
            .expect("selected");
    let error = handshake
        .finish(
            &headers(&[b"permessage-deflate", b"permessage-deflate"]),
            PmdComposition::Compatible,
        )
        .expect_err("one selection only");
    assert_eq!(error, NegotiationError::ResponseAltered);
}

// ---------------------------------------------------------------- configuration

#[test]
fn local_compressor_windows_are_validated_not_clamped() {
    for bits in [0, 7, 8, 16, 255] {
        assert_eq!(
            ClientConfig::new().client_max_window_bits(bits).unwrap_err(),
            ConfigError::WindowBits,
            "client local window {bits}"
        );
        assert_eq!(
            ServerConfig::new().server_max_window_bits(bits).unwrap_err(),
            ConfigError::WindowBits,
            "server local window {bits}"
        );
    }
    for bits in 9..=15 {
        assert!(ClientConfig::new().client_max_window_bits(bits).is_ok());
        assert!(ServerConfig::new().server_max_window_bits(bits).is_ok());
    }
}

#[test]
fn peer_windows_admit_eight() {
    assert!(ClientConfig::new().server_max_window_bits(8).is_ok());
    assert!(ServerConfig::new().client_max_window_bits(8).is_ok());
    for bits in [0, 7, 16, 255] {
        assert_eq!(
            ClientConfig::new().server_max_window_bits(bits).unwrap_err(),
            ConfigError::PeerWindowBits,
            "client bound on the server window {bits}"
        );
        assert_eq!(
            ServerConfig::new().client_max_window_bits(bits).unwrap_err(),
            ConfigError::PeerWindowBits,
            "server bound on the client window {bits}"
        );
    }
}

// ------------------------------------------------------ validate-composition

/// The attestation gates the agreement, so the interesting rows are the two
/// where PMD was actually selected and the two where it was not: a conflict only
/// means something when there is a compressed stream for it to be about.
#[test]
fn a_conflicting_extension_set_produces_no_client_agreement() {
    let error = client_round_trip_composing(
        ClientConfig::new(),
        &[b"permessage-deflate"],
        PmdComposition::Conflict,
    )
    .expect_err("a conflicting set must not agree");
    assert_eq!(error, NegotiationError::ExtensionConflict);
}

#[test]
fn a_conflicting_extension_set_produces_no_server_agreement() {
    let handshake =
        ServerHandshake::accept(ServerConfig::new(), &headers(&[b"permessage-deflate"]))
            .expect("the request is conforming")
            .expect("selected");
    let error = handshake
        .finish(&headers(&[b"permessage-deflate"]), PmdComposition::Conflict)
        .expect_err("a conflicting set must not agree");
    assert_eq!(error, NegotiationError::ExtensionConflict);
}

#[test]
fn composition_is_irrelevant_when_the_server_declined() {
    let agreed = client_round_trip_composing(ClientConfig::new(), &[], PmdComposition::Conflict)
        .expect("a declined extension cannot conflict with anything");
    assert!(agreed.is_none());
}

#[test]
fn composition_is_irrelevant_when_the_response_dropped_the_selection() {
    let handshake =
        ServerHandshake::accept(ServerConfig::new(), &headers(&[b"permessage-deflate"]))
            .expect("the request is conforming")
            .expect("selected");
    let agreed = handshake
        .finish(&headers(&[]), PmdComposition::Conflict)
        .expect("removing the selection is how a host declines a conflicting set");
    assert!(agreed.is_none());
}

/// A duplicated selection is caught by counting, which happens after the loop,
/// so this is the row that pins the order of the arms rather than an early
/// return. Without it the conflict check can widen to every count and still look
/// correct: the removal row is decided by an earlier arm and cannot see it.
#[test]
fn a_duplicated_response_outranks_a_composition_conflict() {
    let handshake =
        ServerHandshake::accept(ServerConfig::new(), &headers(&[b"permessage-deflate"]))
            .expect("the request is conforming")
            .expect("selected");
    let error = handshake
        .finish(&headers(&[b"permessage-deflate", b"permessage-deflate"]), PmdComposition::Conflict)
        .expect_err("both faults are present");
    assert_eq!(error, NegotiationError::ResponseAltered);
}

/// A rewritten response is a host bug about the response, and a conflicting set
/// is a host bug about the extension list. Both are fatal; this pins which one
/// is reported so the host is told what it actually got wrong.
#[test]
fn a_rewritten_response_outranks_a_composition_conflict() {
    let handshake = ServerHandshake::accept(
        ServerConfig::new(),
        &headers(&[b"permessage-deflate; client_max_window_bits"]),
    )
    .expect("the request is conforming")
    .expect("selected");
    let error = handshake
        .finish(
            &headers(&[b"permessage-deflate; client_max_window_bits=10"]),
            PmdComposition::Conflict,
        )
        .expect_err("both faults are present");
    assert_eq!(error, NegotiationError::ResponseAltered);
}
