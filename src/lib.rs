// src/lib.rs  –  plugin entry point
mod imp;
pub mod srtla;

use glib::prelude::*;

// ─── Public GObject wrapper ───────────────────────────────────────────────────
glib::wrapper! {
    pub struct SrtlaSink(ObjectSubclass<imp::SrtlaSink>)
        @extends gst::Bin, gst::Element, gst::Object;
}

impl SrtlaSink {
    pub fn new(name: Option<&str>) -> Self {
        glib::Object::builder()
            .property("name", name.unwrap_or("srtlasink"))
            .build()
    }
}

// ─── Plugin registration ──────────────────────────────────────────────────────
fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "srtlasink",
        gst::Rank::NONE,
        SrtlaSink::static_type(),
    )?;
    Ok(())
}

gst::plugin_define!(
    srtla,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    "MIT/X11",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_HOMEPAGE"),
    env!("BUILD_REL_DATE")
);
