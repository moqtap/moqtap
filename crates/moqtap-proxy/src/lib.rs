#![deny(missing_docs)]

//! MoQT intercepting proxy — transparent stream forwarding with inline
//! frame parsing and observation.
//!
//! This crate provides a transparent proxy that sits between a MoQT client
//! and relay, forwarding all bytes bidirectionally while parsing MoQT frames
//! inline to emit structured events. It does not participate in MoQT state
//! management — it observes and optionally mutates, but never acts as an
//! endpoint.

pub mod error;
pub mod event;
pub mod hook;
pub mod listener;
pub mod observer;
pub mod parser;
pub mod proxy;
pub mod session;

#[cfg(feature = "cert-gen")]
pub mod cert;
