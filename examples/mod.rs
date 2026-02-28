use bevy::prelude::*;

/// Corner of the screen where the FPS counter will appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(unused)]
pub enum Anchor {
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
}

impl Default for Anchor {
    fn default() -> Self {
        Anchor::TopLeft
    }
}

/// Resource produced from the plugin field so the systems can read the
/// selected anchor at runtime.
#[derive(Resource)]
pub struct FpsAnchor(pub Anchor);

/// Marker component for the text entity that we update each frame.
#[derive(Component)]
struct FpsText;

/// Spawn the text bundle and position it according to [`FpsAnchor`].
fn setup_fps_display(mut commands: Commands, anchor: Res<FpsAnchor>) {
    let style = match anchor.0 {
        Anchor::TopLeft => Node {
            position_type: PositionType::Absolute,
            top: Val::Px(5.0),
            left: Val::Px(5.0),
            ..Default::default()
        },
        Anchor::TopRight => Node {
            position_type: PositionType::Absolute,
            top: Val::Px(5.0),
            right: Val::Px(5.0),
            ..Default::default()
        },
        Anchor::BottomLeft => Node {
            position_type: PositionType::Absolute,
            bottom: Val::Px(5.0),
            left: Val::Px(5.0),
            ..Default::default()
        },
        Anchor::BottomRight => Node {
            position_type: PositionType::Absolute,
            bottom: Val::Px(5.0),
            right: Val::Px(5.0),
            ..Default::default()
        },
    };

    commands
        .spawn((
            Text(String::from("FPS: ...")),
            // match the styling pattern from other examples
            TextFont {
                font_size: 20.0,
                ..default()
            },
            TextColor(Color::WHITE),
            style,
            FpsText,
        ));
}

/// Each frame compute FPS from the `Time` resource and update the text.
fn update_fps_text(
    time: Res<Time>,
    mut query: Query<(&mut Text, &mut TextColor), With<FpsText>>,
) {
    // avoid a divide-by-zero just in case
    let fps = if time.delta_secs() > 0.0 {
        1.0 / time.delta_secs()
    } else {
        0.0
    };
    // determine how "red" the colour should be: at 10fps we want full red, and
    // it linearly falls off for higher frame rates. we clamp so that the value
    // stays in 0..=1.
    let red_intensity = if fps > 0.0 {
        (10.0 / fps).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let colour = Color::linear_rgb(red_intensity, 1.0 - red_intensity, 0.0);

    for (mut text, mut text_color) in query.iter_mut() {
        text.0 = format!("FPS: {:.0}", fps);
        text_color.0 = colour;
    }
}

// A simple text/string asset used in the examples.  the helper macro generates
// the struct, a loader, and a plugin that registers the loader + DLC type.
bevy_dlc::dlc_simple_asset!(TextAsset, TextAssetLoader, TextAssetPlugin, "txt", "json",);

#[derive(serde::Serialize, serde::Deserialize, Reflect, Clone, Debug)]
pub struct Person {
    pub age: u32,
    pub city: String,
}

#[derive(Asset, Reflect, serde::Serialize, serde::Deserialize)]
pub struct JsonAsset(pub std::collections::HashMap<String, Person>);

/// A very small helper plugin used by the `examples` crates.  In
/// addition to registering the diagnostics plugins we use it to spawn a
/// simple FPS counter that can be anchored to any corner of the screen.
///
/// The anchor is stored as a field on the plugin so callers can customise it
/// when they add the plugin (`.add_plugins(ExamplePlugin { fps_anchor:
/// Anchor::BottomRight })`).  The plugin will convert the value into a
/// resource that the systems can read.
pub struct ExamplePlugin {
    /// Where on the screen the FPS counter should be positioned.  Defaults to
    /// [`Anchor::TopLeft`].
    pub fps_anchor: Anchor,
}

impl Default for ExamplePlugin {
    fn default() -> Self {
        ExamplePlugin {
            fps_anchor: Anchor::TopRight,
        }
    }
}

impl Plugin for ExamplePlugin {
    fn build(&self, app: &mut App) {
        // diagnostics plugin is still handy for other debugging, but we
        // compute the FPS ourselves from the `Time` resource rather than
        // pulling a value out of a non-resource type.
        app.insert_resource(FpsAnchor(self.fps_anchor))
            .add_systems(Startup,setup_fps_display)
            .add_systems(Update,update_fps_text);
    }
}

#[allow(unused)]
fn main() {}
