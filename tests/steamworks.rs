mod common;

#[cfg(feature = "steam")]
mod steam_tests {
    use crate::common::prelude::*;
    use bevy_dlc::steamworks::{register_steam_path, SteamDlcPlugin};
    use bevy_dlc::{DlcPack, PackItem};
    use bevy::prelude::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_steam_asset_reader_mock() {
        // 1. Setup App with SteamDlcPlugin
        let mut t = TestAppBuilder::new("test_product", &["dlcA"])
            .add_plugins(SteamDlcPlugin)
            .with_default_plugins()
            .add_plugins(TextAssetPlugin::<TextAsset>::default())
            .build();

        // 2. Create a mock Steam folder
        let steam_id = 123456u64;
        let temp_steam_dir = tempfile::tempdir().expect("create temp steam dir");
        let steam_path = temp_steam_dir.path();

        // 3. Register the mock path
        register_steam_path(steam_id, steam_path.to_path_buf());

        // 4. Place a .txt file
        let test_data = "hello from steam";
        let file_name = "test.txt";
        std::fs::write(steam_path.join(file_name), test_data).expect("write file");

        // 5. Load the asset via steam:// protocol
        let asset_path = format!("steam://{}/{}", steam_id, file_name);
        
        t.update();

        let asset_server = t.resource::<AssetServer>();
        let handle: Handle<TextAsset> = asset_server.load(asset_path);
        
        t.wait_for_asset(&handle);
        
        let assets = t.resource::<Assets<TextAsset>>();
        let text_asset = assets.get(&handle).expect("text asset loaded");
        assert_eq!(text_asset.0, "hello from steam"); 
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_steam_dlc_pack_loading() {
        let mut t = TestAppBuilder::new("test_product", &["dlcA"])
            .add_plugins(SteamDlcPlugin)
            .with_default_plugins()
            .add_plugins(TextAssetPlugin::<TextAsset>::default())
            .build();

        let steam_id = 777777u64;
        let temp_steam_dir = tempfile::tempdir().expect("create temp steam dir");
        let steam_path = temp_steam_dir.path().to_path_buf();
        register_steam_path(steam_id, steam_path.clone());

        // Prepare a pack
        let items = vec![
            PackItem::new("inner.txt", b"inner dlc content".to_vec()).with_extension("txt"),
        ];
        
        let signed = t.signed_license();
        let enc_key = bevy_dlc::extract_encrypt_key_from_license(&signed).expect("key");
        let dlc_key = t.dlc_key.clone();
        let product = t.product.clone();
        
        let pack_bytes = bevy_dlc::pack_encrypted_pack(
            &bevy_dlc::DlcId::from("dlcA"),
            &items,
            &product,
            &dlc_key,
            &enc_key,
        ).expect("pack");

        let pack_filename = "dlcA.dlcpack";
        std::fs::write(steam_path.join(pack_filename), pack_bytes).expect("write pack");

        // Load the pack via steam://
        let pack_url = format!("steam://{}/{}", steam_id, pack_filename);
        let pack_handle: Handle<DlcPack> = t.resource::<AssetServer>().load(pack_url);
        
        t.wait_for_asset(&pack_handle);

        // Load asset FROM pack using label
        let asset_url = format!("steam://{}/{}#inner.txt", steam_id, pack_filename);
        let asset_handle: Handle<TextAsset> = t.resource::<AssetServer>().load(asset_url);
        
        t.wait_for_asset(&asset_handle);
        
        let assets = t.resource::<Assets<TextAsset>>();
        let text_asset = assets.get(&asset_handle).expect("inner asset loaded");
        assert_eq!(text_asset.0, "inner dlc content");
    }
}
