mod bus;
mod model;
mod ui;

use adw::prelude::*;
use color_eyre::{Result, eyre::eyre};
use gtk::gio;
use std::cell::RefCell;

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // No registration and no approval provider if a graphical display cannot
    // be initialized. GTK and all widgets stay on this OS main thread.
    adw::init()
        .map_err(|_| eyre!("cannot initialize GTK/libadwaita display; approval unavailable"))?;
    let app = adw::Application::builder()
        .application_id("io.github.pineapplehunter.TpmPasskey1.Approval")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let (sender, receiver) = async_channel::bounded(16);
    let shared = model::Shared::new(sender);
    let display = gtk::gdk::Display::default().ok_or_else(|| eyre!("GTK display unavailable"))?;
    if display.is_closed() {
        return Err(eyre!("GTK display is closed"));
    }
    let display_shared = shared.clone();
    let display_app = app.downgrade();
    display.connect_closed(move |_, _| {
        display_shared.shutdown();
        if let Some(app) = display_app.upgrade() {
            app.quit();
        }
    });
    let pending_receiver = RefCell::new(Some(receiver));
    let ui_shared = shared.clone();
    app.connect_activate(move |app| {
        if let Some(receiver) = pending_receiver.borrow_mut().take() {
            ui::run(app, ui_shared.clone(), receiver);
        }
    });
    // Keep the user-service agent alive while no request window is open.
    let _hold = app.hold();
    bus::start(shared.clone())?;
    let status = app.run();
    shared.shutdown();
    if status != gtk::glib::ExitCode::SUCCESS {
        return Err(eyre!("GTK application stopped unexpectedly"));
    }
    Ok(())
}
