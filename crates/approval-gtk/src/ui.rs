use crate::model::{Event, Shared, plain_text, wording};
use adw::prelude::*;
use gtk::{gdk, glib};
use std::{cell::Cell, rc::Rc, time::Instant};
use tpm_passkey_protocol::ApprovalContext;

fn label(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_use_markup(false);
    label.set_wrap(true);
    label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    label.set_xalign(0.0);
    label.set_selectable(true);
    label
}
fn field(container: &gtk::Box, name: &str, value: &str, prominent: bool) {
    if value.is_empty() {
        return;
    }
    let heading = label(name);
    heading.add_css_class("heading");
    container.append(&heading);
    let value = label(&plain_text(value));
    if prominent {
        value.add_css_class("title-3");
    }
    container.append(&value);
}

struct Dialog {
    native: adw::AlertDialog,
    presented: Rc<Cell<bool>>,
}
impl std::ops::Deref for Dialog {
    type Target = adw::AlertDialog;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
impl Dialog {
    fn present(&self, parent: Option<&gtk::Widget>) {
        self.presented.set(true);
        self.native.present(parent);
    }
}
fn dismiss(dialog: &Dialog) {
    // Responses already close native dialogs. Track presentation independently
    // of mapping so cancellation also catches a not-yet-mapped presentation.
    if dialog.presented.replace(false) {
        dialog.native.force_close();
    }
}

fn dialog(shared: &Shared, token: u64, context: &ApprovalContext, deadline: Instant) -> Dialog {
    let (title, explanation) = wording(context);
    let dialog = adw::AlertDialog::new(Some(title), Some(&explanation));
    let presented = Rc::new(Cell::new(false));
    dialog.set_title(title);
    dialog.set_heading_use_markup(false);
    dialog.set_body_use_markup(false);
    dialog.set_content_width(540);
    dialog.add_response("deny", "Deny");
    dialog.add_response(
        "allow",
        if context.operation == "reset" {
            "Delete all passkeys"
        } else {
            "Allow"
        },
    );
    dialog.set_close_response("deny");
    dialog.set_default_response(Some("deny"));
    dialog.set_response_appearance(
        "allow",
        if context.operation == "reset" {
            adw::ResponseAppearance::Destructive
        } else {
            adw::ResponseAppearance::Suggested
        },
    );

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let details = gtk::Box::new(gtk::Orientation::Vertical, 8);
    field(&details, "Website (full RP ID)", &context.rp_id, true);
    field(
        &details,
        "Website display name (unverified)",
        &context.rp_name,
        false,
    );
    if context.operation == "register" {
        field(
            &details,
            "Registration account",
            &context.account_name,
            false,
        );
        field(
            &details,
            "Registration account ID",
            &context.account_id,
            false,
        );
    }
    let scroll = gtk::ScrolledWindow::builder()
        .child(&details)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .max_content_height(300)
        .propagate_natural_height(true)
        .build();
    content.append(&scroll);
    let note = label(
        "Approve only an action you just initiated. This confirms user presence, not PIN or biometric verification.",
    );
    note.add_css_class("dim-label");
    content.append(&note);
    dialog.set_extra_child(Some(&content));

    let response_shared = shared.clone();
    let response_presented = presented.clone();
    dialog.connect_response(None, move |dialog, response| {
        response_presented.set(false);
        dialog.set_response_enabled("deny", false);
        dialog.set_response_enabled("allow", false);
        response_shared.decide(token, response == "allow");
    });
    // AlertDialog emits the configured close response for ordinary window close.
    // If a widget disappears without that signal, deny on the next main-loop
    // iteration, after any normal response handler has had a chance to run.
    let unrealize_shared = shared.clone();
    let unrealize_presented = presented.clone();
    dialog.connect_unrealize(move |_| {
        unrealize_presented.set(false);
        let shared = unrealize_shared.clone();
        glib::idle_add_local_once(move || shared.decide(token, false));
    });
    let keys = gtk::EventControllerKey::new();
    keys.set_propagation_phase(gtk::PropagationPhase::Capture);
    let key_shared = shared.clone();
    let key_presented = presented.clone();
    let weak_dialog = dialog.downgrade();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            key_shared.decide(token, false);
            if let Some(dialog) = weak_dialog.upgrade() {
                if key_presented.replace(false) {
                    dialog.force_close();
                }
            }
            return glib::Propagation::Stop;
        }
        // Enter never approves, even after focus navigation. Pointer or Space
        // on an explicitly focused response is required for an affirmative.
        if key == gdk::Key::Return || key == gdk::Key::KP_Enter {
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    dialog.add_controller(keys);
    let timeout_shared = shared.clone();
    let timeout_presented = presented.clone();
    let weak_dialog = dialog.downgrade();
    glib::timeout_add_local_once(
        deadline.saturating_duration_since(Instant::now()),
        move || {
            timeout_shared.decide(token, false);
            if let Some(dialog) = weak_dialog.upgrade() {
                if timeout_presented.replace(false) {
                    dialog.force_close();
                }
            }
        },
    );
    Dialog {
        native: dialog,
        presented,
    }
}

pub fn run(_app: &adw::Application, shared: Shared, events: async_channel::Receiver<Event>) {
    glib::MainContext::default().spawn_local(async move {
        let mut current: Option<(u64, Dialog)> = None;
        while let Ok(event) = events.recv().await {
            if current
                .as_ref()
                .is_some_and(|(token, _)| !shared.active(*token))
            {
                if let Some((_, dialog)) = current.take() {
                    dismiss(&dialog);
                }
            }
            match event {
                Event::Show {
                    token,
                    context,
                    deadline,
                } => {
                    if !shared.active(token) {
                        continue;
                    }
                    if current.is_some() {
                        shared.decide(token, false);
                        continue;
                    }
                    let dialog = dialog(&shared, token, &context, deadline);
                    dialog.present(None::<&gtk::Widget>);
                    if let Some(deny) = dialog.default_widget() {
                        adw::prelude::AdwDialogExt::set_focus(&*dialog, Some(&deny));
                        deny.grab_focus();
                    }
                    current = Some((token, dialog));
                }
                Event::Dismiss(token) => {
                    if current.as_ref().is_some_and(|(active, _)| *active == token) {
                        if let Some((_, dialog)) = current.take() {
                            dismiss(&dialog);
                        }
                    }
                }
            }
        }
        shared.set_owner(None);
        if let Some((_, dialog)) = current.take() {
            dismiss(&dialog);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn button(widget: &impl IsA<gtk::Widget>, text: &str) -> Option<gtk::Button> {
        let widget = widget.as_ref();
        if let Some(button) = widget.downcast_ref::<gtk::Button>() {
            if button.label().as_deref() == Some(text) {
                return Some(button.clone());
            }
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            if let Some(found) = button(&widget, text) {
                return Some(found);
            }
            child = widget.next_sibling();
        }
        None
    }
    #[test]
    #[ignore = "requires a real GTK display (e.g. Xvfb) and a session bus"]
    fn gtk_dialog_smoke() {
        adw::init().expect("GTK/libadwaita display");
        let app = adw::Application::builder()
            .application_id("io.github.pineapplehunter.TpmPasskey1.ApprovalSmoke")
            .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
            .build();
        app.register(None::<&gtk::gio::Cancellable>).unwrap();
        let (sender, _events) = async_channel::bounded(32);
        let shared = Shared::new(sender);
        shared.set_owner(Some(":1.42".into()));
        let context = ApprovalContext {
            operation: "register".into(),
            rp_id: "example.org".into(),
            rp_name: "<b>Not markup</b>".into(),
            account_name: "alice".into(),
            account_id: "01".into(),
            credential_count: 0,
        };
        for (id, allow) in [("deny", false), ("allow", true)] {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (token, mut answer) = shared
                .begin(":1.42", id, context.clone(), deadline)
                .unwrap();
            let dialog = dialog(&shared, token, &context, deadline);
            dialog.present(None::<&gtk::Widget>);
            assert_eq!(dialog.default_response().as_deref(), Some("deny"));
            assert_eq!(dialog.close_response(), "deny");
            assert!(!dialog.is_body_use_markup() && !dialog.is_heading_use_markup());
            let deny = button(&*dialog, "Deny").expect("native Deny response");
            let yes = button(&*dialog, "Allow").expect("native Allow response");
            adw::prelude::AdwDialogExt::set_focus(&*dialog, Some(&deny));
            assert_eq!(
                adw::prelude::AdwDialogExt::focus(&*dialog),
                Some(deny.clone().upcast())
            );
            yes.grab_focus();
            let controllers = dialog.observe_controllers();
            let keys = (0..controllers.n_items())
                .find_map(|i| {
                    controllers
                        .item(i)
                        .and_then(|v| v.downcast::<gtk::EventControllerKey>().ok())
                })
                .unwrap();
            assert!(keys.emit_by_name::<bool>(
                "key-pressed",
                &[&gdk::Key::Return, &0u32, &gdk::ModifierType::empty()]
            ));
            assert!(shared.active(token));
            if allow {
                yes.emit_clicked();
            } else {
                deny.emit_clicked();
            }
            assert_eq!(answer.try_recv().unwrap(), allow);
            assert_eq!(shared.complete(token, ":1.42", true), allow);
            assert!(!dialog.is_response_enabled("deny"));
            assert!(!dialog.is_response_enabled("allow"));
            // Users cannot click disabled native responses. Inject a duplicate
            // at the consent-state boundary, not by illegally re-emitting a
            // closed AlertDialog's private button action.
            shared.decide(token, !allow);
            assert!(!shared.complete(token, ":1.42", true));
            dismiss(&dialog);
        }
        for id in ["close", "escape", "cancel", "timeout"] {
            let deadline = Instant::now()
                + if id == "timeout" {
                    Duration::from_millis(30)
                } else {
                    Duration::from_secs(5)
                };
            let (token, mut answer) = shared
                .begin(":1.42", id, context.clone(), deadline)
                .unwrap();
            let dialog = dialog(&shared, token, &context, deadline);
            dialog.present(None::<&gtk::Widget>);
            if id == "close" {
                dialog.close();
            }
            if id == "cancel" {
                dismiss(&dialog);
                dismiss(&dialog);
            }
            if id == "escape" {
                let controllers = dialog.observe_controllers();
                let keys = (0..controllers.n_items())
                    .find_map(|i| {
                        controllers
                            .item(i)
                            .and_then(|v| v.downcast::<gtk::EventControllerKey>().ok())
                    })
                    .unwrap();
                assert!(keys.emit_by_name::<bool>(
                    "key-pressed",
                    &[&gdk::Key::Escape, &0u32, &gdk::ModifierType::empty()]
                ));
            }
            let main = glib::MainContext::default();
            let limit = Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(allow) = answer.try_recv() {
                    assert!(!allow);
                    break;
                }
                assert!(Instant::now() < limit);
                main.iteration(false);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(!shared.complete(token, ":1.42", true));
            dismiss(&dialog);
        }
        let untrusted = label("<b>plain text</b>");
        assert!(!untrusted.uses_markup());
        assert_eq!(untrusted.text().as_str(), "<b>plain text</b>");
        let mut reset = context;
        reset.operation = "reset".into();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (token, _) = shared
            .begin(":1.42", "reset", reset.clone(), deadline)
            .unwrap();
        let dialog = dialog(&shared, token, &reset, deadline);
        assert_eq!(
            dialog.response_appearance("allow"),
            adw::ResponseAppearance::Destructive
        );
        dismiss(&dialog);
    }
}
