use bevy_dlc::prelude::*;
use secure_gate::ExposeSecret;

fn main() {
    // generate a demo keypair
    let dlc_key = DlcKey::generate_random();
    let wrapped: SignedLicense = dlc_key
        .create_signed_license(&["expansionA"], Product::from("my-game"))
        .expect("create wrapped license");
    wrapped.with_secret(|s| println!("SIGNED LICENSE={}", s));
    // printing the DlcKey uses the base64url public-key (Display impl)
    println!("PUBKEY={}", dlc_key);
}
