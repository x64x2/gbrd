use std::fmt::{Debug, Formatter, Result as FmtResult};

use uuid::Uuid;

use super::side::{self, Side};
use crate::{Authenticate as AuthenticateHeader, Header};

/// The model of the `Authenticate` command
pub struct Authenticate<M> {
	inner:   Side<Tx, Rx>,
	_marker: M,
}

struct Tx {
	header: Header,
}

impl Authenticate<side::Tx> {
	pub(super) fn new(uuid: Uuid, password: impl AsRef<[u8]>, exporter: &impl KeyingMaterialExporter) -> Self {
		Self {
			inner:   Side::Tx(Tx {
				header: Header::Authenticate(AuthenticateHeader::new(
					uuid,
					exporter.export_keying_material(uuid.as_ref(), password.as_ref()),
				)),
			}),
			_marker: side::Tx,
		}
	}
	pub fn header(&self) -> &Header {
		let Side::Tx(tx) = &self.inner else { unreachable!() };
		&tx.header
	}
}

impl Debug for Authenticate<side::Tx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let Side::Tx(tx) = &self.inner else { unreachable!() };
		f.debug_struct("Authenticate").field("header", &tx.header).finish()
	}
}

struct Rx {
	uuid:  Uuid,
	token: [u8; 32],
}

impl Authenticate<side::Rx> {
	pub(super) fn new(uuid: Uuid, token: [u8; 32]) -> Self {
		Self {
			inner:   Side::Rx(Rx { uuid, token }),
			_marker: side::Rx,
		}
	}
	pub fn uuid(&self) -> Uuid {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		rx.uuid
	}
	pub fn token(&self) -> [u8; 32] {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		rx.token
	}
	pub fn is_valid(&self, password: impl AsRef<[u8]>, exporter: &impl KeyingMaterialExporter) -> bool {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		rx.token == exporter.export_keying_material(rx.uuid.as_ref(), password.as_ref())
	}
}

impl Debug for Authenticate<side::Rx> {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		let Side::Rx(rx) = &self.inner else { unreachable!() };
		f.debug_struct("Authenticate")
			.field("uuid", &rx.uuid)
			.field("token", &rx.token)
			.finish()
	}
}

pub trait KeyingMaterialExporter {
	fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32];
}
