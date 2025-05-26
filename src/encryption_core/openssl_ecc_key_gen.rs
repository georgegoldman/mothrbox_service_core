pub struct OpensslEccKeyGen;

impl OpensslEccKeyGen {
    fn generate_key(&self)-> [u8;16]
    {
        let nid = openssl::nid::Nid::X9_62_PRIME256V1;
        let group = openssl::ec::EcGroup::from_curve_name(nid).expect("Failed to create EC group from the curve name");
        let key = openssl::ec::EcKey::generate(&group).expect("Failed to generate group");
        let _ctx = openssl::bn::BigNumContext::new().expect("Failed making context");
        let private_key = key.private_key().to_vec();
        let iv = key.private_key().to_vec();
        
        let slice = &private_key[..16];
        let key16: [u8; 16] = slice.try_into().expect("Slice must be 16 bytes");
        

        key16
    }

    fn generate_iv(&self) -> [u8;16] {
        let nid = openssl::nid::Nid::X9_62_PRIME256V1;
        let group = openssl::ec::EcGroup::from_curve_name(nid).expect("Failed to create EC group from the curve name");
        let key = openssl::ec::EcKey::generate(&group).expect("Failed to generate group");
        let _ctx = openssl::bn::BigNumContext::new().expect("Failed making context");
        let iv = key.private_key().to_vec();

        let slice_iv = &iv[..16];
        let key16_iv: [u8; 16] = slice_iv.try_into().expect("Slice must be 16 byte");

        key16_iv
    }

    pub fn get_key(&self)-> [u8;16] {self.generate_key()}
    pub fn get_iv(&self) -> [u8;16] {self.generate_iv()}
}