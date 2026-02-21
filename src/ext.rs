use bevy::prelude::*;

use crate::{DlcLoader, asset_loader};

pub trait AppExt {
    /// Register a `DlcLoader` for the given asset type `T`. This is required for any asset type
    /// that may be loaded from a DLC pack. The plugin registers loaders for common asset types
    /// (Image, Scene, Mesh, Font, AudioSource, etc.) but you must register loaders for any custom
    /// asset types.
    ///
    /// **Important**: As of `v2.0`, this function also calls `init_asset::<T>()` to register the asset type itself, so you do not need to call `init_asset` separately.
    ///
    /// **Suggestion**: If I missed a common asset type that should be supported out-of-the-box,
    /// please open an issue or PR to add it!
    fn register_dlc_type<T: Asset>(&mut self) -> &mut Self;
}

impl AppExt for App {
    fn register_dlc_type<T: Asset>(&mut self) -> &mut Self {
        self.init_asset::<T>();
        self.init_asset_loader::<DlcLoader<T>>();

        // ensure a factory entry exists so `DlcPackLoader` will include a
        // `TypedSubAssetRegistrar::<T>` when it (re)registers. This allows
        // `register_dlc_type` to be called *before* or *after* the plugin is
        // added and still result in the pack loader supporting `T`.
        let tname = T::type_path();
        if let Some(factories_res) = self
            .world_mut()
            .get_resource_mut::<asset_loader::DlcPackRegistrarFactories>()
        {
            let mut inner = factories_res.0.write().unwrap();
            if !inner.iter().any(|f| f.type_name() == tname) {
                inner.push(Box::new(asset_loader::TypedRegistrarFactory::<T>::default()));
            }
        } else {
            let mut v: Vec<Box<dyn asset_loader::DlcPackRegistrarFactory>> = Vec::new();
            v.push(Box::new(asset_loader::TypedRegistrarFactory::<T>::default()));
            self.insert_resource(asset_loader::DlcPackRegistrarFactories(
                std::sync::Arc::new(std::sync::RwLock::new(v)),
            ));
        }
        self
    }
}
