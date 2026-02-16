use bevy_dlc::prelude::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn main() {
    // generate a demo keypair and produce a signed token
    let dlc_key = DlcKey::generate_random();
    let signedlicense = dlc_key
        .create_signed_license(&["expansionA"], Some(Product::from("my-game".to_string())), None, None)
        .expect("create privatekey");

    println!("LICENSE_STR={}", signedlicense.expose_secret());
    println!("PUBKEY={}", URL_SAFE_NO_PAD.encode(dlc_key.public_key_bytes()));
}
