//! A session that closes while the Setup exchange is still in progress, on all
//! fourteen drafts.
//!
//! Every draft says the same thing in its Termination section: "The Transport
//! Session can be terminated at any point." Eight of them then oblige an
//! endpoint to terminate during the Setup exchange itself. Drafts 07 through 14
//! say so in their Versions section — "If the server does not support any of
//! the versions offered by the client, or the client receives a server version
//! that it did not offer, the corresponding peer MUST close the session" — and
//! from draft-11 that sentence names an error code. Drafts 15 through 19 dropped
//! the sentence and kept the code: VERSION_NEGOTIATION_FAILED (0x15), "The
//! client didn't offer a version supported by the server".
//!
//! On drafts 07 through 14 a version mismatch is discoverable only from the
//! Setup exchange, so a state machine that cannot close there cannot carry out
//! the close those drafts demand. A machine whose `on_close` accepts only
//! `Active` and `Draining` cannot, and the arm that admits `SetupExchange` is
//! one line in one place in each of the fourteen modules, which is why every
//! draft is gated separately.
//!
//! # Draft-20 is here for the first sentence only
//!
//! It has no VERSION_NEGOTIATION_FAILED: draft-20's changelog records the row
//! being taken out — "Remove the VERSION_NEGOTIATION_FAILED session error
//! (#1867)" — and no other code replaces it. Nothing is left for such a code
//! to report, because draft-20 performs version negotiation in the ALPN; it is
//! the drafts before 15 that negotiate in the SETUP messages. So the one code
//! that names a Setup-time outcome on drafts 11 through 19 is the one code
//! draft-20 has not got.
//!
//! Which leaves the Termination sentence, and that is enough on its own: a
//! session may be terminated at any point, the Setup exchange is a point, and a
//! machine that refuses there is wrong whether or not a registered code names
//! the reason. On draft-20 this gate is therefore a pure regression guard, and
//! it earns its place as one: nothing else in the file would say if draft-20's
//! `on_close` lost its `SetupExchange` arm.
//!
//! `Connecting` still refuses, and that is asserted too. It is the state before
//! any transport exists, so there is no session to terminate rather than a
//! session that may not be.

/// The three gates for one draft.
macro_rules! close_during_setup_gates {
    ($draft:ident, $feat:literal, $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::{
                SessionError, SessionState, SessionStateMachine,
            };
            use $role as Role;

            /// The session closes with the Setup exchange still unfinished.
            ///
            /// `Closed` afterwards is what says so: it is reachable from
            /// nowhere else in this test, so a close that had been refused
            /// would leave the machine in `SetupExchange`.
            ///
            /// # Ablation
            ///
            /// `SetupExchange` removed from `on_close`, measured on
            /// draft-19:
            ///
            /// ```text
            /// thread 'draft19::a_session_closes_before_it_is_established'
            /// panicked at crates\moqtap-client\tests\close_during_setup.rs:
            /// a session may be terminated at any point: InvalidTransition { from: SetupExchange, to: Closed }
            /// ```
            ///
            /// The endpoint gate below fails with it, on the same line and
            /// wrapped in its own error:
            ///
            /// ```text
            /// thread 'draft19::an_endpoint_closes_before_it_is_established'
            /// panicked at crates\moqtap-client\tests\close_during_setup.rs:
            /// an endpoint may terminate at any point: Session(InvalidTransition { from: SetupExchange, to: Closed })
            /// ```
            ///
            /// The same cut in draft-20's `on_close` establishes that the
            /// draft-20 arm can fail too. It
            /// reddens these two gates on draft-20 and nothing else in the
            /// file — 40 passed, 2 failed — which is the count that says the
            /// third gate below is a control and not a copy: it asserts the
            /// `Connecting` refusal, which the cut does not touch.
            #[test]
            fn a_session_closes_before_it_is_established() {
                let mut sm = SessionStateMachine::new();
                sm.on_connect().expect("the control stream is opened");
                assert_eq!(sm.state(), SessionState::SetupExchange);
                sm.on_close().unwrap_or_else(|e| {
                    panic!("a session may be terminated at any point: {:?}", e)
                });
                assert_eq!(sm.state(), SessionState::Closed);
            }

            /// The endpoint reaches the same close, so the `SetupExchange` arm
            /// is not stranded one layer below its only caller.
            #[test]
            fn an_endpoint_closes_before_it_is_established() {
                let mut endpoint = Endpoint::new(Role::Client);
                endpoint.connect().expect("the control stream is opened");
                assert_eq!(endpoint.session_state(), SessionState::SetupExchange);
                endpoint
                    .close()
                    .unwrap_or_else(|e| panic!("an endpoint may terminate at any point: {:?}", e));
                assert_eq!(endpoint.session_state(), SessionState::Closed);
            }

            /// Before the transport exists there is no session to terminate.
            #[test]
            fn a_session_that_never_connected_has_nothing_to_terminate() {
                let mut sm = SessionStateMachine::new();
                assert_eq!(sm.state(), SessionState::Connecting);
                match sm.on_close() {
                    Ok(()) => panic!("a session was closed before any transport was established"),
                    Err(SessionError::InvalidTransition { from, .. }) => {
                        assert_eq!(from, SessionState::Connecting)
                    }
                }
            }
        }
    };
}

close_during_setup_gates!(draft07, "draft07", moqtap_client::draft07::endpoint::Role);
close_during_setup_gates!(draft08, "draft08", moqtap_client::draft08::endpoint::Role);
close_during_setup_gates!(draft09, "draft09", moqtap_client::draft09::endpoint::Role);
close_during_setup_gates!(draft10, "draft10", moqtap_client::draft10::endpoint::Role);
close_during_setup_gates!(draft11, "draft11", moqtap_client::draft11::session::request_id::Role);
close_during_setup_gates!(draft12, "draft12", moqtap_client::draft12::session::request_id::Role);
close_during_setup_gates!(draft13, "draft13", moqtap_client::draft13::session::request_id::Role);
close_during_setup_gates!(draft14, "draft14", moqtap_client::draft14::session::request_id::Role);
close_during_setup_gates!(draft15, "draft15", moqtap_client::draft15::session::request_id::Role);
close_during_setup_gates!(draft16, "draft16", moqtap_client::draft16::session::request_id::Role);
close_during_setup_gates!(draft17, "draft17", moqtap_client::draft17::session::request_id::Role);
close_during_setup_gates!(draft18, "draft18", moqtap_client::draft18::session::request_id::Role);
close_during_setup_gates!(draft19, "draft19", moqtap_client::draft19::session::request_id::Role);
close_during_setup_gates!(draft20, "draft20", moqtap_client::draft20::session::request_id::Role);
