

pub struct WalrusOp;


impl WalrusOp {
    pub async  fn write_to_walrus(encrypted_data: Vec<u8>) {
        let client = reqwest::Client::new();

        let res = client
        .post("https://universal-dehlia-mothrbox-b59d2011.koyeb.app/write_to_walrus/")
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_data)
        .send()
        .await.unwrap();
        
        let json: serde_json::Value = res.json().await.unwrap();
        
    }
}