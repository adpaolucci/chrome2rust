use crate::state::{AppState, WorkspaceTab};
use crate::views::{
    cache_list::render_cache_list,
    console_tree::render_console_tree,
    forensic_tabs::{
        render_creds_tab, render_extensions_tab, render_findings_tab, render_history_tab, render_overview_tab,
        render_sessions_tab, render_timeline_tab,
    },
    inspector_pane::render_inspector_pane,
    modals::render_modals,
    ribbon::render_ribbon,
    status_bar::render_status_bar,
};
use eframe::egui::{self, Color32, Stroke};

pub struct Chrome2RustApp {
    pub state: AppState,
}

impl Chrome2RustApp {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl eframe::App for Chrome2RustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.state.first_frame {
            self.state.first_frame = false;
            if let Some(p) = self.state.initial_load_path.take() {
                self.state.start_load(p, ctx);
            }
        }

        self.state.poll_worker(ctx);
        self.state.handle_shortcuts(ctx);

        let win_face = Color32::from_rgb(236, 233, 216);
        let win_border = Color32::from_rgb(172, 168, 153);

        // 1. Classic Win32 Menu Bar + Target Toolbar
        render_ribbon(ctx, &mut self.state);

        // 2. Classic Win32 Multi-Segment Sunken Status Bar
        render_status_bar(ctx, &self.state);

        // 3. Left Pane: MMC Console Tree (Profiles & Workspaces)
        if self.state.show_console_tree {
            egui::SidePanel::left("left_console_tree")
                .resizable(true)
                .default_width(240.0)
                .width_range(180.0..=360.0)
                .frame(
                    egui::Frame::NONE
                        .fill(win_face)
                        .stroke(Stroke::new(1.0_f32, win_border))
                        .inner_margin(egui::Margin::same(3)),
                )
                .show(ctx, |ui| {
                    render_console_tree(ui, &mut self.state, ctx);
                });
        }

        // 4. Right Details Property Sheet when inside Cache Inspector
        if self.state.active_tab == WorkspaceTab::CacheInspector && self.state.show_preview_pane {
            egui::SidePanel::right("cache_preview_panel")
                .resizable(true)
                .default_width(370.0)
                .width_range(240.0..=620.0)
                .frame(
                    egui::Frame::NONE
                        .fill(win_face)
                        .stroke(Stroke::new(1.0_f32, win_border))
                        .inner_margin(egui::Margin::same(3)),
                )
                .show(ctx, |ui| {
                    render_inspector_pane(ui, &mut self.state);
                });
        }

        // 5. Center Content Workspace
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(win_face).inner_margin(egui::Margin::same(3)))
            .show(ctx, |ui| match self.state.active_tab {
                WorkspaceTab::CacheInspector => render_cache_list(ui, &mut self.state, ctx),
                WorkspaceTab::Overview => render_overview_tab(ui, &mut self.state),
                WorkspaceTab::Findings => render_findings_tab(ui, &mut self.state),
                WorkspaceTab::Timeline => render_timeline_tab(ui, &mut self.state),
                WorkspaceTab::HistoryDownloads => render_history_tab(ui, &mut self.state),
                WorkspaceTab::CredsCookies => render_creds_tab(ui, &mut self.state),
                WorkspaceTab::ExtensionsBookmarks => render_extensions_tab(ui, &mut self.state),
                WorkspaceTab::SessionsStorage => render_sessions_tab(ui, &mut self.state),
            });

        // 6. Active Win32 Modal Dialogs
        render_modals(ctx, &mut self.state);
    }
}
