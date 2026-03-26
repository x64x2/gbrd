use uuid::Uuid;
/// the client raw password is hashed into a 256-bit long token using [TLS Keying Material Exporter](https://www.rfc-editor.org/rfc/rfc5705) on current TLS session. while exporting, the `label` should be the client UUID and the `context` should be the raw password.
#[derive(Clone, Debug)]
pub struct Authenticate {
	uuid:  Uuid,
	token: [u8; 32],
}

impl Authenticate {
	const TYPE_CODE: u8 = 0x00;
	pub const fn new(uuid: Uuid, token: [u8; 32]) -> Self {
		Self { uuid, token }
	}

	pub fn uuid(&self) -> Uuid {
		self.uuid
	}

	pub fn token(&self) -> [u8; 32] {
		self.token
	}

	pub const fn type_code() -> u8 {
		Self::TYPE_CODE
	}

	#[allow(clippy::len_without_is_empty)]
	pub fn len(&self) -> usize {
		16 + 32
	}
}

impl From<Authenticate> for (Uuid, [u8; 32]) {
	fn from(auth: Authenticate) -> Self {
		(auth.uuid, auth.token)
	}
}
