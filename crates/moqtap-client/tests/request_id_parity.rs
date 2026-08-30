//! Request ID allocation, on every draft that has request IDs.
//!
//! Two endpoints share one ID space and stay out of each other's way by
//! parity: the client takes the even numbers and the server the odd ones, and
//! each steps by two. An endpoint that steps by one looks correct for exactly
//! one request and then starts issuing its peer's IDs, which the drafts make a
//! session close rather than a warning. That is the failure these gates exist
//! for, and it is why they drive every draft rather than one: the rule is the
//! same sentence in nine documents, and it was implemented three different
//! ways.
//!
//! Drafts 17 and later removed MAX_REQUEST_ID, so the ceiling gates stop at
//! draft-16.

/// Allocation and parity, for one draft.
///
/// `$budget` is `Some(n)` on the drafts where an allocator starts blocked and
/// has to be granted a ceiling first, and `None` where MAX_REQUEST_ID is gone
/// and the ceiling is already unlimited.
macro_rules! allocator_suite {
    ($feature:literal, $draft:ident, $budget:expr) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use moqtap_client::$draft::session::request_id::{
                RequestIdAllocator, RequestIdError, Role,
            };

            fn granted(role: Role) -> RequestIdAllocator {
                let mut alloc = RequestIdAllocator::new(role);
                if let Some(max) = $budget {
                    alloc.update_max(max).expect("a fresh allocator has a ceiling of 0");
                }
                alloc
            }

            /// "The client's Request ID starts at 0 and are even and the
            /// server's Request ID starts at 1 and are odd. The Request ID
            /// increments by 2 ..."
            ///
            /// Four IDs rather than one, because a step of one is right about
            /// the first ID on both sides and wrong about every one after it.
            ///
            /// Stepping by one instead fails with:
            ///
            /// ```text
            /// assertion `left == right` failed: a client allocates the even IDs
            ///   left: [0, 1, 2, 3]
            ///  right: [0, 2, 4, 6]
            /// ```
            #[test]
            fn each_role_allocates_its_own_half_of_the_id_space() {
                let mut client = granted(Role::Client);
                let client_ids: Vec<u64> =
                    (0..4).map(|_| client.allocate().unwrap().into_inner()).collect();
                assert_eq!(client_ids, vec![0, 2, 4, 6], "a client allocates the even IDs");

                let mut server = granted(Role::Server);
                let server_ids: Vec<u64> =
                    (0..4).map(|_| server.allocate().unwrap().into_inner()).collect();
                assert_eq!(server_ids, vec![1, 3, 5, 7], "a server allocates the odd IDs");
            }

            /// The two halves are checked against each other rather than
            /// against a hand-written list, so a parity inverted in both the
            /// allocator and the validator at once - which would let an
            /// implementation talk to itself and to nothing else - still fails.
            ///
            /// Inverting the expected parity in `validate_peer_id` fails
            /// with:
            ///
            /// ```text
            /// assertion `left == right` failed: a Client refused 1, which a Server allocates
            ///   left: Err(WrongParity(1, Server))
            ///  right: Ok(())
            /// ```
            #[test]
            fn each_role_accepts_only_the_ids_the_other_role_allocates() {
                for (role, peer_role) in
                    [(Role::Client, Role::Server), (Role::Server, Role::Client)]
                {
                    let mut mine = granted(role);
                    let mut theirs = granted(peer_role);
                    for _ in 0..4 {
                        let peer_id = theirs.allocate().unwrap().into_inner();
                        assert_eq!(
                            mine.validate_peer_id(peer_id),
                            Ok(()),
                            "a {role:?} refused {peer_id}, which a {peer_role:?} allocates",
                        );
                        let own_id = mine.allocate().unwrap().into_inner();
                        assert_eq!(
                            mine.validate_peer_id(own_id),
                            Err(RequestIdError::WrongParity(own_id, peer_role)),
                            "a {role:?} accepted {own_id} from the peer, an ID it allocates itself",
                        );
                    }
                }
            }
        }
    };
}

/// The MAX_REQUEST_ID ceiling, for one draft that has one.
macro_rules! ceiling_suite {
    ($feature:literal, $mod_name:ident, $draft:ident) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::{
                RequestIdAllocator, RequestIdError, Role,
            };
            use moqtap_codec::varint::VarInt;

            /// MAX_REQUEST_ID carries one past the largest usable ID, and a
            /// request ID "equal to or larger than this" closes the session
            /// with Too Many Requests. So a ceiling of 4 leaves a client the
            /// two IDs 0 and 2, and 4 itself is the first it may not send.
            ///
            /// Making the comparison inclusive fails with:
            ///
            /// ```text
            /// assertion `left == right` failed: 4 is the ceiling itself, which the draft refuses
            ///   left: Ok(4)
            ///  right: Err(Blocked)
            /// ```
            #[test]
            fn the_ceiling_is_exclusive() {
                let mut alloc = RequestIdAllocator::new(Role::Client);
                alloc.update_max(4).unwrap();
                assert_eq!(alloc.allocate().map(VarInt::into_inner), Ok(0));
                assert_eq!(alloc.allocate().map(VarInt::into_inner), Ok(2));
                assert_eq!(
                    alloc.allocate().map(VarInt::into_inner),
                    Err(RequestIdError::Blocked),
                    "4 is the ceiling itself, which the draft refuses",
                );
            }

            /// The setup parameter's default is 0, and the drafts read that as
            /// "the peer MUST NOT send requests" - which only holds if a
            /// ceiling of 0 forbids the ID 0 as well.
            #[test]
            fn a_ceiling_of_zero_allows_nothing() {
                let mut alloc = RequestIdAllocator::new(Role::Client);
                assert!(alloc.is_blocked(), "a fresh allocator has granted nothing");
                assert_eq!(alloc.allocate().map(VarInt::into_inner), Err(RequestIdError::Blocked));
            }

            /// "The Maximum Request ID MUST only increase within a session",
            /// and a peer that receives an equal or smaller value closes the
            /// session. The ceiling starts at 0, so 0 is not a legal first
            /// advertisement either - there is no opening case in which a
            /// repeat is allowed.
            ///
            /// Exempting the opening value from the check fails with:
            ///
            /// ```text
            /// 0 is the value the ceiling already has
            /// ```
            #[test]
            fn an_advertised_ceiling_must_strictly_increase_from_the_first_message() {
                let mut endpoint = Endpoint::new(Role::Client);
                assert!(
                    endpoint.send_max_request_id(VarInt::from_u64(0).unwrap()).is_err(),
                    "0 is the value the ceiling already has",
                );
                endpoint.send_max_request_id(VarInt::from_u64(4).unwrap()).unwrap();
                assert!(
                    endpoint.send_max_request_id(VarInt::from_u64(4).unwrap()).is_err(),
                    "a repeat is not an increase",
                );
            }

            /// A peer's request ID is measured against the ceiling *this*
            /// endpoint advertised, never the one the peer granted us. The two
            /// are different numbers, and an endpoint that has advertised
            /// nothing refuses every peer ID.
            ///
            /// Measuring against the allocator's own `max_id` instead fails
            /// with:
            ///
            /// ```text
            /// 1 is below the ceiling
            /// ```
            ///
            /// which is the second assertion rather than the first: an
            /// allocator that was never granted anything also has a ceiling of
            /// 0, so swapping the two numbers still refuses everything at the
            /// start and only diverges once one of them moves.
            #[test]
            fn peer_ids_are_measured_against_what_this_endpoint_advertised() {
                let mut endpoint = Endpoint::new(Role::Client);
                assert!(
                    endpoint.validate_peer_request_id(1).is_err(),
                    "an endpoint that has advertised nothing has granted nothing",
                );

                endpoint.send_max_request_id(VarInt::from_u64(4).unwrap()).unwrap();
                assert!(endpoint.validate_peer_request_id(1).is_ok(), "1 is below the ceiling");
                assert!(endpoint.validate_peer_request_id(3).is_ok(), "3 is below the ceiling");
                assert!(
                    endpoint.validate_peer_request_id(5).is_err(),
                    "5 is past the advertised ceiling",
                );
                assert!(
                    endpoint.validate_peer_request_id(2).is_err(),
                    "2 belongs to this endpoint's half of the space",
                );
            }
        }
    };
}

/// The same strictly-increasing rule on the drafts that call the ceiling
/// MAX_SUBSCRIBE_ID and whose endpoints carry no role.
macro_rules! subscribe_id_ceiling_suite {
    ($feature:literal, $mod_name:ident, $draft:ident) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_codec::varint::VarInt;

            /// "The Maximum Subscribe Id MUST only increase within a session,
            /// and receipt of a MAX_SUBSCRIBE_ID message with an equal or
            /// smaller Subscribe ID value is a 'Protocol Violation'." The
            /// starting value is 0, so 0 is not a legal first advertisement.
            ///
            /// Exempting the opening value from the check fails with:
            ///
            /// ```text
            /// 0 is the value the ceiling already has
            /// ```
            #[test]
            fn an_advertised_ceiling_must_strictly_increase_from_the_first_message() {
                // Built through `Default` rather than `new`, because these four
                // drafts do not agree on whether an endpoint has a role and
                // this rule does not turn on the answer: the ceiling a peer is
                // held to is the one this endpoint advertised, whichever side
                // it is.
                let mut endpoint = Endpoint::default();
                assert!(
                    endpoint.send_max_subscribe_id(VarInt::from_u64(0).unwrap()).is_err(),
                    "0 is the value the ceiling already has",
                );
                endpoint.send_max_subscribe_id(VarInt::from_u64(4).unwrap()).unwrap();
                assert!(
                    endpoint.send_max_subscribe_id(VarInt::from_u64(4).unwrap()).is_err(),
                    "a repeat is not an increase",
                );
            }
        }
    };
}

allocator_suite!("draft11", draft11, Some(64));
allocator_suite!("draft12", draft12, Some(64));
allocator_suite!("draft13", draft13, Some(64));
allocator_suite!("draft14", draft14, Some(64));
allocator_suite!("draft15", draft15, Some(64));
allocator_suite!("draft16", draft16, Some(64));
allocator_suite!("draft17", draft17, None::<u64>);
allocator_suite!("draft18", draft18, None::<u64>);
allocator_suite!("draft19", draft19, None::<u64>);

ceiling_suite!("draft11", ceiling11, draft11);
ceiling_suite!("draft12", ceiling12, draft12);
ceiling_suite!("draft13", ceiling13, draft13);
ceiling_suite!("draft14", ceiling14, draft14);
ceiling_suite!("draft15", ceiling15, draft15);
ceiling_suite!("draft16", ceiling16, draft16);

subscribe_id_ceiling_suite!("draft07", ceiling07, draft07);
subscribe_id_ceiling_suite!("draft08", ceiling08, draft08);
subscribe_id_ceiling_suite!("draft09", ceiling09, draft09);
subscribe_id_ceiling_suite!("draft10", ceiling10, draft10);
