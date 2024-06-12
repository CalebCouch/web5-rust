pub struct GeneralJws {
  payload: String,
  signatures: Vec<SignatureEntry>
};

pub struct SignatureEntry {
  protected: String,
  signature: String
}
