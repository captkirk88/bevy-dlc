use bevy_dlc::prelude::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn main() {
    // generate a demo keypair and produce a signed token
    let (dlc_key, _pubkey) = DlcKey::generate_complete();
    let privatekey = dlc_key
        .create_private_token(&["expansionA"], Some(Product::from("my-game".to_string())), None, None)
        .expect("create privatekey");

    println!("TOKEN_STR={}", privatekey.expose_secret());
    println!("PUBKEY={}", URL_SAFE_NO_PAD.encode(dlc_key.public_key_bytes()));
}
