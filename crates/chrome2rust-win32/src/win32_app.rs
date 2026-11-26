use crate::LaunchArgs;
use crate::win32_dialogs::{copy_to_clipboard, pick_folder, pick_save_file};
use crate::win32_state::{ContentQuickCat, CredSubTab, HistorySubTab, PreviewMode, SessionSubTab, Win32State};
use chrome2rust_cache::CacheSortField;
use chrome2rust_cache::export::ExportFormat;
use chrome2rust_core::time::format_local_opt;
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_report::ReportFormat;
use chrome2rust_report::markdown::format_bytes;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use winsafe::{self as w, co, gui, msg, prelude::*};

const TIMER_POLL_ID: usize = 1;
const MAX_WIN32_LIST_ROWS: usize = 10_000;

// Menu command IDs
const IDM_OPEN_FOLDER: u16 = 4001;
const IDM_LOAD_DEFAULT_BROWSER: u16 = 4002;
const IDM_EXTRACT_CACHE: u16 = 4003;
const IDM_EXPORT_CSV: u16 = 4004;
const IDM_EXPORT_JSON: u16 = 4005;
const IDM_EXPORT_TSV: u16 = 4011;
const IDM_EXPORT_TABULAR: u16 = 4012;
const IDM_EXPORT_TEXT: u16 = 4013;
const IDM_EXPORT_HTML_H: u16 = 4014;
const IDM_EXPORT_HTML_V: u16 = 4015;
const IDM_EXPORT_XML: u16 = 4016;
const IDM_EXPORT_URLS: u16 = 4017;
const IDM_REPORT_HTML: u16 = 4006;
const IDM_REPORT_JSON: u16 = 4007;
const IDM_REPORT_MD: u16 = 4008;
const IDM_REPORT_ALL: u16 = 4009;
const IDM_EXIT: u16 = 4010;

const IDM_COPY_URLS: u16 = 4020;
const IDM_COPY_TSV: u16 = 4021;
const IDM_COPY_PREVIEW: u16 = 4022;
const IDM_DELETE_CACHE: u16 = 4023;
const IDM_ENTRY_PROPS: u16 = 4024;

const IDM_TOGGLE_ZERO: u16 = 4030;
const IDM_TOGGLE_MILLIS: u16 = 4031;
const IDM_PREVIEW_AUTO: u16 = 4032;
const IDM_PREVIEW_HEADERS: u16 = 4033;
const IDM_PREVIEW_HEX: u16 = 4034;
const IDM_TOGGLE_DETECTED_EXT: u16 = 4035;
const IDM_TOGGLE_WEBSITE_DIRS: u16 = 4036;
const IDM_TOGGLE_PEANUTS: u16 = 4037;

const IDM_CUSTODY_AUDIT: u16 = 4040;
const IDM_TAB_BASE: u16 = 4050;
const IDM_ABOUT: u16 = 4060;

fn lbl(parent: &(impl GuiParent + 'static), text: &str, x: i32, y: i32, w_dp: i32) -> gui::Label {
    gui::Label::new(
        parent,
        gui::LabelOpts {
            text,
            position: gui::dpi(x, y),
            size: gui::dpi(w_dp, 18),
            ..Default::default()
        },
    )
}

fn edit(
    parent: &(impl GuiParent + 'static),
    x: i32,
    y: i32,
    w_dp: i32,
    h_dp: i32,
    resize: (gui::Horz, gui::Vert),
) -> gui::Edit {
    gui::Edit::new(
        parent,
        gui::EditOpts {
            position: gui::dpi(x, y),
            width: gui::dpi_x(w_dp),
            height: gui::dpi_y(h_dp),
            resize_behavior: resize,
            ..Default::default()
        },
    )
}

fn chk(parent: &(impl GuiParent + 'static), text: &str, x: i32, y: i32) -> gui::CheckBox {
    gui::CheckBox::new(
        parent,
        gui::CheckBoxOpts {
            text,
            position: gui::dpi(x, y),
            ..Default::default()
        },
    )
}

fn btn(
    parent: &(impl GuiParent + 'static),
    text: &str,
    x: i32,
    y: i32,
    w_dp: i32,
    h_dp: i32,
    resize: (gui::Horz, gui::Vert),
) -> gui::Button {
    gui::Button::new(
        parent,
        gui::ButtonOpts {
            text,
            position: gui::dpi(x, y),
            width: gui::dpi_x(w_dp),
            height: gui::dpi_y(h_dp),
            resize_behavior: resize,
            ..Default::default()
        },
    )
}

fn tab_page(parent: &(impl GuiParent + 'static)) -> gui::TabPage {
    gui::TabPage::new(
        parent,
        gui::TabPageOpts {
            class_bg_brush: gui::Brush::Color(co::COLOR::BTNFACE),
            ..Default::default()
        },
    )
}

fn move_ctrl(ctrl: &impl GuiWindow, x: i32, y: i32, w: i32, h: i32) {
    if *ctrl.hwnd() != w::HWND::NULL {
        let _ = ctrl.hwnd().SetWindowPos(
            w::HwndPlace::None,
            w::POINT::with(x, y),
            w::SIZE::with(w.max(10), h.max(10)),
            co::SWP::NOZORDER,
        );
    }
}

fn make_list(
    parent: &(impl GuiParent + 'static),
    x: i32,
    y: i32,
    w_dp: i32,
    h_dp: i32,
    cols: &[(&str, i32)],
    sort_hdr: bool,
) -> gui::ListView {
    let style = if sort_hdr {
        co::LVS::REPORT | co::LVS::SHOWSELALWAYS
    } else {
        co::LVS::REPORT | co::LVS::NOSORTHEADER | co::LVS::SHOWSELALWAYS
    };
    let scaled_cols: Vec<(&str, i32)> = cols.iter().map(|(t, w)| (*t, gui::dpi_x(*w))).collect();
    gui::ListView::new(
        parent,
        gui::ListViewOpts {
            position: gui::dpi(x, y),
            size: gui::dpi(w_dp, h_dp),
            control_style: style,
            columns: &scaled_cols,
            ..Default::default()
        },
    )
}

fn readonly_multiline(parent: &(impl GuiParent + 'static), x: i32, y: i32, w_dp: i32, h_dp: i32) -> gui::Edit {
    gui::Edit::new(
        parent,
        gui::EditOpts {
            position: gui::dpi(x, y),
            width: gui::dpi_x(w_dp),
            height: gui::dpi_y(h_dp),
            control_style: co::ES::MULTILINE | co::ES::READONLY | co::ES::AUTOVSCROLL | co::ES::AUTOHSCROLL,
            window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::VISIBLE | co::WS::VSCROLL | co::WS::HSCROLL,
            ..Default::default()
        },
    )
}

#[derive(Clone)]
struct CachePage {
    page: gui::TabPage,
    filter_edit: gui::Edit,
    cat_combo: gui::ComboBox,
    chk_no_zero: gui::CheckBox,
    btn_prev_auto: gui::Button,
    btn_prev_hdr: gui::Button,
    btn_prev_hex: gui::Button,
    btn_copy_url: gui::Button,
    btn_copy_tsv: gui::Button,
    btn_props: gui::Button,
    btn_delete: gui::Button,
    list: gui::ListView,
    inspector: gui::Edit,
}

impl CachePage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "Filter:", 10, 12, 42);
        let filter_edit = edit(&page, 54, 9, 210, 22, (gui::Horz::None, gui::Vert::None));
        let cat_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(270, 9),
                width: gui::dpi_x(115),
                items: &["All Types", "Images", "HTML", "JS / CSS", "JSON / XML", "Media / Fonts"],
                selected_item: Some(0),
                ..Default::default()
            },
        );
        let chk_no_zero = chk(&page, "Hide 0B", 392, 11);

        let btn_prev_auto = btn(&page, "Auto", 470, 8, 52, 24, (gui::Horz::None, gui::Vert::None));
        let btn_prev_hdr = btn(&page, "Headers", 525, 8, 64, 24, (gui::Horz::None, gui::Vert::None));
        let btn_prev_hex = btn(&page, "Hex", 592, 8, 48, 24, (gui::Horz::None, gui::Vert::None));
        let btn_copy_url = btn(&page, "Copy URL", 648, 8, 72, 24, (gui::Horz::None, gui::Vert::None));
        let btn_copy_tsv = btn(&page, "Copy TSV", 724, 8, 72, 24, (gui::Horz::None, gui::Vert::None));
        let btn_props = btn(&page, "Props", 800, 8, 56, 24, (gui::Horz::None, gui::Vert::None));
        let btn_delete = btn(&page, "Delete", 860, 8, 60, 24, (gui::Horz::None, gui::Vert::None));

        let list = make_list(
            &page,
            10,
            38,
            600,
            450,
            &[
                ("URL", 270),
                ("Content-Type", 125),
                ("Detected Type", 125),
                ("Ext", 50),
                ("Size", 80),
                ("Mismatch", 68),
                ("Response", 95),
                ("Last Accessed", 135),
                ("Cache Name", 110),
            ],
            true,
        );
        let inspector = readonly_multiline(&page, 616, 38, 340, 450);

        {
            let list = list.clone();
            let inspector = inspector.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let gap = gui::dpi_x(8);
                let top = gui::dpi_y(38);
                let body_h = (h - top - gui::dpi_y(8)).max(gui::dpi_y(120));
                let insp_w = ((w - 2 * pad) / 3).clamp(gui::dpi_x(260), gui::dpi_x(440));
                let list_w = (w - 2 * pad - gap - insp_w).max(gui::dpi_x(260));
                move_ctrl(&list, pad, top, list_w, body_h);
                move_ctrl(&inspector, pad + list_w + gap, top, insp_w, body_h);
                Ok(())
            });
        }

        Self {
            page,
            filter_edit,
            cat_combo,
            chk_no_zero,
            btn_prev_auto,
            btn_prev_hdr,
            btn_prev_hex,
            btn_copy_url,
            btn_copy_tsv,
            btn_props,
            btn_delete,
            list,
            inspector,
        }
    }
}

#[derive(Clone)]
struct OverviewPage {
    page: gui::TabPage,
    btn_html: gui::Button,
    btn_json: gui::Button,
    btn_md: gui::Button,
    btn_bundle: gui::Button,
    summary_edit: gui::Edit,
    domains_list: gui::ListView,
}

impl OverviewPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "Forensic Summary && Offline Report Export:", 10, 12, 320);
        let btn_html = btn(
            &page,
            "Save HTML...",
            350,
            8,
            95,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let btn_json = btn(
            &page,
            "Save JSON...",
            450,
            8,
            95,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let btn_md = btn(
            &page,
            "Save Markdown...",
            550,
            8,
            115,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let btn_bundle = btn(
            &page,
            "Save Bundle (All)...",
            670,
            8,
            130,
            24,
            (gui::Horz::None, gui::Vert::None),
        );

        let summary_edit = readonly_multiline(&page, 10, 38, 940, 185);
        lbl(&page, "Top Domains by Activity:", 10, 232, 220);
        let domains_list = make_list(
            &page,
            10,
            254,
            940,
            235,
            &[
                ("Domain", 340),
                ("History Visits", 110),
                ("Cache Items", 105),
                ("Cache Size", 120),
                ("Cookies", 100),
            ],
            false,
        );

        {
            let summary_edit = summary_edit.clone();
            let domains_list = domains_list.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let full_w = (w - 2 * pad).max(gui::dpi_x(240));
                let sum_h = gui::dpi_y(185);
                move_ctrl(&summary_edit, pad, gui::dpi_y(38), full_w, sum_h);
                let dom_y = gui::dpi_y(254);
                move_ctrl(
                    &domains_list,
                    pad,
                    dom_y,
                    full_w,
                    (h - dom_y - gui::dpi_y(8)).max(gui::dpi_y(100)),
                );
                Ok(())
            });
        }

        Self {
            page,
            btn_html,
            btn_json,
            btn_md,
            btn_bundle,
            summary_edit,
            domains_list,
        }
    }
}

#[derive(Clone)]
struct FindingsPage {
    page: gui::TabPage,
    sev_combo: gui::ComboBox,
    search_edit: gui::Edit,
    btn_apply: gui::Button,
    list: gui::ListView,
    evidence_edit: gui::Edit,
}

impl FindingsPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "Severity:", 10, 12, 62);
        let sev_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(75, 9),
                width: gui::dpi_x(120),
                items: &["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                selected_item: Some(0),
                ..Default::default()
            },
        );
        lbl(&page, "Search:", 208, 12, 52);
        let search_edit = edit(&page, 264, 9, 280, 22, (gui::Horz::None, gui::Vert::None));
        let btn_apply = btn(&page, "Filter", 552, 8, 72, 24, (gui::Horz::None, gui::Vert::None));

        let list = make_list(
            &page,
            10,
            38,
            940,
            290,
            &[
                ("Severity", 85),
                ("Profile", 110),
                ("Category", 145),
                ("Title", 250),
                ("Summary", 340),
            ],
            false,
        );
        let evidence_edit = readonly_multiline(&page, 10, 336, 940, 150);

        {
            let list = list.clone();
            let evidence_edit = evidence_edit.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let top = gui::dpi_y(38);
                let ev_h = gui::dpi_y(145);
                let gap = gui::dpi_y(8);
                let list_h = (h - top - ev_h - gap - gui::dpi_y(8)).max(gui::dpi_y(120));
                let full_w = (w - 2 * pad).max(gui::dpi_x(240));
                move_ctrl(&list, pad, top, full_w, list_h);
                move_ctrl(&evidence_edit, pad, top + list_h + gap, full_w, ev_h);
                Ok(())
            });
        }

        Self {
            page,
            sev_combo,
            search_edit,
            btn_apply,
            list,
            evidence_edit,
        }
    }
}

#[derive(Clone)]
struct SimpleFilterListPage {
    page: gui::TabPage,
    mode_combo: gui::ComboBox,
    search_edit: gui::Edit,
    btn_apply: gui::Button,
    info_lbl: gui::Label,
    list: gui::ListView,
}

impl SimpleFilterListPage {
    fn new(
        parent: &(impl GuiParent + 'static),
        mode_lbl: &str,
        modes: &[&str],
        cols: &[(&str, i32)],
        default_info: &str,
    ) -> Self {
        let page = tab_page(parent);

        lbl(&page, mode_lbl, 10, 12, 72);
        let mode_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(84, 9),
                width: gui::dpi_x(205),
                items: modes,
                selected_item: Some(0),
                ..Default::default()
            },
        );
        lbl(&page, "Search:", 300, 12, 52);
        let search_edit = edit(&page, 355, 9, 250, 22, (gui::Horz::None, gui::Vert::None));
        let btn_apply = btn(&page, "Apply", 612, 8, 70, 24, (gui::Horz::None, gui::Vert::None));
        let info_lbl = lbl(&page, default_info, 10, 38, 920);
        let list = make_list(&page, 10, 60, 940, 425, cols, false);

        {
            let list = list.clone();
            let info_lbl = info_lbl.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let full_w = (w - 2 * pad).max(gui::dpi_x(240));
                move_ctrl(&info_lbl, pad, gui::dpi_y(38), full_w, gui::dpi_y(18));
                let list_y = gui::dpi_y(60);
                move_ctrl(
                    &list,
                    pad,
                    list_y,
                    full_w,
                    (h - list_y - gui::dpi_y(8)).max(gui::dpi_y(120)),
                );
                Ok(())
            });
        }

        Self {
            page,
            mode_combo,
            search_edit,
            btn_apply,
            info_lbl,
            list,
        }
    }
}

#[derive(Clone)]
struct BrowserToolsPage {
    page: gui::TabPage,
    tool_combo: gui::ComboBox,
    filter_edit: gui::Edit,
    btn_apply: gui::Button,
    btn_export: gui::Button,
    info_lbl: gui::Label,
    list: gui::ListView,
    inspector: gui::Edit,
}

impl BrowserToolsPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);
        lbl(&page, "Tool:", 10, 12, 38);
        let tool_names = [
            "fx_cache (Firefox Cache2)",
            "fx_history (Firefox History)",
            "fx_cookies (Firefox Cookies Metadata)",
            "fx_bookmarks (Firefox Bookmarks)",
            "fx_downloads (Firefox Downloads)",
            "fx_formhistory (Firefox Form History)",
            "fx_addons (Firefox Add-ons)",
            "fx_sessions (Firefox Sessions)",
            "opera_cache (Opera Cache)",
            "opera_history (Opera History)",
            "safari_cache (Safari Cache.db)",
            "safari_history (Safari History)",
            "safari_bookmarks (Safari Bookmarks)",
            "unified_history (Unified History)",
            "unified_downloads (Unified Downloads)",
            "unified_addons (Unified Add-ons)",
            "unified_bookmarks (Unified Bookmarks)",
            "unified_autofill (Unified Autofill)",
            "search_queries (Search Queries)",
            "carve_images (Image Carver + EXIF)",
            "carve_video (Video Carver + Reassembly)",
        ];
        let tool_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(52, 9),
                width: gui::dpi_x(250),
                items: &tool_names,
                selected_item: Some(0),
                ..Default::default()
            },
        );
        lbl(&page, "Filter:", 312, 12, 42);
        let filter_edit = edit(&page, 356, 9, 220, 22, (gui::Horz::None, gui::Vert::None));
        let btn_apply = btn(&page, "Apply", 584, 8, 68, 24, (gui::Horz::None, gui::Vert::None));
        let btn_export = btn(
            &page,
            "Export CSV...",
            660,
            8,
            96,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let info_lbl = lbl(
            &page,
            "Select any of the 21 non-credential browser tools or media carvers above.",
            10,
            38,
            920,
        );

        let list = make_list(
            &page,
            10,
            60,
            940,
            260,
            &[
                ("Column 1", 220),
                ("Column 2", 220),
                ("Column 3", 220),
                ("Column 4", 220),
            ],
            false,
        );
        let inspector = readonly_multiline(&page, 10, 328, 940, 150);

        {
            let list = list.clone();
            let inspector = inspector.clone();
            let info_lbl = info_lbl.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let full_w = (w - 2 * pad).max(gui::dpi_x(240));
                move_ctrl(&info_lbl, pad, gui::dpi_y(38), full_w, gui::dpi_y(18));
                let list_y = gui::dpi_y(60);
                let insp_h = gui::dpi_y(145);
                let gap = gui::dpi_y(8);
                let list_h = (h - list_y - insp_h - gap - gui::dpi_y(8)).max(gui::dpi_y(120));
                move_ctrl(&list, pad, list_y, full_w, list_h);
                move_ctrl(&inspector, pad, list_y + list_h + gap, full_w, insp_h);
                Ok(())
            });
        }

        Self {
            page,
            tool_combo,
            filter_edit,
            btn_apply,
            btn_export,
            info_lbl,
            list,
            inspector,
        }
    }
}

#[derive(Clone)]
struct Win32App {
    wnd: gui::WindowMain,
    target_edit: gui::Edit,
    btn_browse: gui::Button,
    btn_load: gui::Button,
    browser_combo: gui::ComboBox,
    btn_open_browser: gui::Button,
    profile_combo: gui::ComboBox,
    chk_decrypt: gui::CheckBox,
    keys_edit: gui::Edit,
    btn_extract: gui::Button,
    btn_export: gui::Button,
    btn_custody: gui::Button,

    tab: gui::Tab,
    tab_pages: Vec<gui::TabPage>,
    cache_pg: CachePage,
    overview_pg: OverviewPage,
    findings_pg: FindingsPage,
    timeline_pg: SimpleFilterListPage,
    history_pg: SimpleFilterListPage,
    creds_pg: SimpleFilterListPage,
    ext_pg: SimpleFilterListPage,
    sess_pg: SimpleFilterListPage,
    browser_pg: BrowserToolsPage,

    status_bar: gui::StatusBar,
    state: Arc<Mutex<Win32State>>,
    suppress_sync: Arc<AtomicBool>,
}

fn build_main_menu() -> w::SysResult<w::HMENU> {
    let menu = w::HMENU::CreateMenu()?;
    let file_m = w::HMENU::CreatePopupMenu()?;
    file_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_OPEN_FOLDER,
            text: "Open User Data / Profile / Cache...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_LOAD_DEFAULT_BROWSER,
            text: "Load Selected Local Browser",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_EXTRACT_CACHE,
            text: "Extract Filtered Cache Payloads...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_CSV,
            text: "Export Cache Table (CSV)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_TSV,
            text: "Export Cache Table (TSV)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_TABULAR,
            text: "Export Cache Table (Tabular Text)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_TEXT,
            text: "Export Cache Table (Plain Text Cards)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_HTML_H,
            text: "Export Cache Table (HTML Horizontal)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_HTML_V,
            text: "Export Cache Table (HTML Vertical)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_XML,
            text: "Export Cache Table (XML)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_JSON,
            text: "Export Cache Table (JSON)...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_URLS,
            text: "Export Cache URLs (.txt)...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_HTML,
            text: "Generate HTML Report...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_JSON,
            text: "Generate JSON Report...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_MD,
            text: "Generate Markdown Report...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_ALL,
            text: "Generate Full Report Bundle...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_EXIT,
            text: "Exit",
        },
    ])?;

    let action_m = w::HMENU::CreatePopupMenu()?;
    action_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_COPY_URLS,
            text: "Copy Cache URLs",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_COPY_TSV,
            text: "Copy Cache Rows (TSV)",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_COPY_PREVIEW,
            text: "Copy Inspector Output",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_ENTRY_PROPS,
            text: "Selected Cache Entry Properties...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_DELETE_CACHE,
            text: "Delete Selected Standalone Cache File...",
        },
    ])?;

    let view_m = w::HMENU::CreatePopupMenu()?;
    view_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_TOGGLE_ZERO,
            text: "Toggle Hide Zero-Length Files",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TOGGLE_MILLIS,
            text: "Toggle Milliseconds in Timestamps",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_TOGGLE_DETECTED_EXT,
            text: "Extraction: Toggle Prefer Detected Extension",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TOGGLE_WEBSITE_DIRS,
            text: "Extraction: Toggle Website Directory Hierarchy",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TOGGLE_PEANUTS,
            text: "Decryption: Toggle Linux 'peanuts' Fallback",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_PREVIEW_AUTO,
            text: "Inspector Mode: Auto",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_PREVIEW_HEADERS,
            text: "Inspector Mode: HTTP Headers && Certs",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_PREVIEW_HEX,
            text: "Inspector Mode: Hex Dump",
        },
    ])?;

    let tools_m = w::HMENU::CreatePopupMenu()?;
    tools_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_CUSTODY_AUDIT,
            text: "Compute && Save SHA-256 Merkle Custody Audit...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE,
            text: "Cache Inspector",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 1,
            text: "Overview && Reports",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 2,
            text: "Forensic Findings",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 3,
            text: "Unified Timeline",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 4,
            text: "History && Downloads",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 5,
            text: "Credentials && Cookies",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 6,
            text: "Extensions && Bookmarks",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 7,
            text: "Sessions && Storage",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_TAB_BASE + 8,
            text: "Multi-Browser && Carvers",
        },
    ])?;

    let help_m = w::HMENU::CreatePopupMenu()?;
    help_m.append_item(&[w::MenuItem::Entry {
        cmd_id: IDM_ABOUT,
        text: "About Chrome2Rust Win32...",
    }])?;

    menu.append_item(&[
        w::MenuItem::Submenu {
            submenu: &file_m,
            text: "&File",
        },
        w::MenuItem::Submenu {
            submenu: &action_m,
            text: "&Action",
        },
        w::MenuItem::Submenu {
            submenu: &view_m,
            text: "&View",
        },
        w::MenuItem::Submenu {
            submenu: &tools_m,
            text: "&Tools",
        },
        w::MenuItem::Submenu {
            submenu: &help_m,
            text: "&Help",
        },
    ])?;
    Ok(menu)
}

pub fn run(launch: LaunchArgs) -> anyhow::Result<()> {
    let hmenu = build_main_menu().map_err(|e| anyhow::anyhow!("Menu creation failed: {e}"))?;
    let state = Arc::new(Mutex::new(Win32State::new(&launch)));

    let wnd = gui::WindowMain::new(gui::WindowMainOpts {
        title: "Chrome2Rust Forensic Workstation (Native Win32)",
        size: gui::dpi(1120, 700),
        style: co::WS::CAPTION
            | co::WS::SYSMENU
            | co::WS::CLIPCHILDREN
            | co::WS::BORDER
            | co::WS::VISIBLE
            | co::WS::SIZEBOX
            | co::WS::MINIMIZEBOX
            | co::WS::MAXIMIZEBOX,
        class_icon: gui::Icon::Id(101),
        class_bg_brush: gui::Brush::Color(co::COLOR::BTNFACE),
        menu: hmenu,
        ..Default::default()
    });

    // Row 1: Target Path & Quick Actions
    lbl(&wnd, "Target:", 10, 12, 48);
    let target_edit = edit(&wnd, 60, 9, 430, 22, (gui::Horz::Resize, gui::Vert::None));
    let btn_browse = btn(&wnd, "Browse...", 496, 8, 76, 24, (gui::Horz::Repos, gui::Vert::None));
    let btn_load = btn(
        &wnd,
        "Load / Refresh",
        576,
        8,
        102,
        24,
        (gui::Horz::Repos, gui::Vert::None),
    );
    let btn_extract = btn(&wnd, "Extract...", 684, 8, 78, 24, (gui::Horz::Repos, gui::Vert::None));
    let btn_export = btn(
        &wnd,
        "Export Table...",
        766,
        8,
        92,
        24,
        (gui::Horz::Repos, gui::Vert::None),
    );
    let btn_custody = btn(
        &wnd,
        "Custody Audit...",
        862,
        8,
        112,
        24,
        (gui::Horz::Repos, gui::Vert::None),
    );

    // Row 2: Browser Discovery, Active Profile & Optional Decryption
    lbl(&wnd, "Browser:", 10, 40, 52);
    let browser_combo = gui::ComboBox::new(
        &wnd,
        gui::ComboBoxOpts {
            position: gui::dpi(64, 37),
            width: gui::dpi_x(210),
            ..Default::default()
        },
    );
    let btn_open_browser = btn(
        &wnd,
        "Load Browser",
        278,
        36,
        92,
        24,
        (gui::Horz::None, gui::Vert::None),
    );

    lbl(&wnd, "Profile:", 378, 40, 46);
    let profile_combo = gui::ComboBox::new(
        &wnd,
        gui::ComboBoxOpts {
            position: gui::dpi(426, 37),
            width: gui::dpi_x(165),
            ..Default::default()
        },
    );

    let chk_decrypt = chk(&wnd, "Decrypt Cookies/Logins", 600, 39);
    lbl(&wnd, "Keys:", 762, 40, 36);
    let keys_edit = edit(&wnd, 800, 37, 174, 22, (gui::Horz::Resize, gui::Vert::None));

    // Tab Pages (8 Forensic Workspaces)
    let cache_pg = CachePage::new(&wnd);
    let overview_pg = OverviewPage::new(&wnd);
    let findings_pg = FindingsPage::new(&wnd);
    let timeline_pg = SimpleFilterListPage::new(
        &wnd,
        "Category:",
        &[
            "All",
            "History",
            "Download",
            "Cache",
            "Cookie",
            "Credential",
            "Bookmark",
            "Extension",
            "Session",
        ],
        &[
            ("Timestamp", 145),
            ("Profile", 90),
            ("Category", 90),
            ("Event", 140),
            ("Target", 255),
            ("Details", 180),
            ("Artifact", 110),
        ],
        "Unified chronological activity across all Chromium artifacts.",
    );
    let history_pg = SimpleFilterListPage::new(
        &wnd,
        "View:",
        &["URLs", "Visits", "Downloads", "Search Terms"],
        &[
            ("Profile", 90),
            ("Time", 145),
            ("Count / State", 120),
            ("Detail / Transition", 180),
            ("Title / Path", 220),
            ("URL / Chain", 260),
        ],
        "Load a Chrome profile to inspect URLs, visits, downloads, search terms, and deletion gaps.",
    );
    let creds_pg = SimpleFilterListPage::new(
        &wnd,
        "View:",
        &["Saved Logins", "Cookies", "Autofill", "Addresses & Cards"],
        &[
            ("Profile", 90),
            ("Origin / Host", 210),
            ("Name / User", 160),
            ("Scheme / Flags", 110),
            ("Value / Status", 220),
            ("Metadata / Expires", 210),
        ],
        "Load a Chrome profile (optionally enable Decrypt + keys above) to inspect credentials, cookies, and autofill.",
    );
    let ext_pg = SimpleFilterListPage::new(
        &wnd,
        "View:",
        &["Installed Extensions", "Bookmarks"],
        &[
            ("Profile", 95),
            ("Name / Folder", 220),
            ("Version / Type", 120),
            ("ID / URL", 280),
            ("Risk Flags / Permissions", 290),
        ],
        "Inspect installed Chrome extensions (permissions && risk flags) and hierarchical bookmarks.",
    );
    let sess_pg = SimpleFilterListPage::new(
        &wnd,
        "View:",
        &[
            "SNSS Open & Closed Tabs",
            "Local Storage (LevelDB)",
            "Session Storage (LevelDB)",
            "IndexedDB, Top Sites & File Inventory",
        ],
        &[
            ("Profile", 95),
            ("Source / Origin", 210),
            ("Key / Tab State", 170),
            ("Value / Title", 240),
            ("Details / Size", 285),
        ],
        "Inspect SNSS session/tab stacks, LevelDB Local/Session Storage, IndexedDB origins, and profile inventory.",
    );

    let browser_pg = BrowserToolsPage::new(&wnd);

    let tab_pages = vec![
        cache_pg.page.clone(),
        overview_pg.page.clone(),
        findings_pg.page.clone(),
        timeline_pg.page.clone(),
        history_pg.page.clone(),
        creds_pg.page.clone(),
        ext_pg.page.clone(),
        sess_pg.page.clone(),
        browser_pg.page.clone(),
    ];

    let tab = gui::Tab::new(
        &wnd,
        gui::TabOpts {
            position: gui::dpi(10, 68),
            size: gui::dpi(1100, 600),
            resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
            pages: &[
                ("Cache Inspector", cache_pg.page.clone()),
                ("Overview && Reports", overview_pg.page.clone()),
                ("Forensic Findings", findings_pg.page.clone()),
                ("Unified Timeline", timeline_pg.page.clone()),
                ("History && Downloads", history_pg.page.clone()),
                ("Credentials && Cookies", creds_pg.page.clone()),
                ("Extensions && Bookmarks", ext_pg.page.clone()),
                ("Sessions && Storage", sess_pg.page.clone()),
                ("Multi-Browser && Carvers", browser_pg.page.clone()),
            ],
            ..Default::default()
        },
    );

    let status_bar = gui::StatusBar::new(
        &wnd,
        &[
            gui::SbPart::Proportional(2),
            gui::SbPart::Fixed(gui::dpi_x(210)),
            gui::SbPart::Fixed(gui::dpi_x(195)),
            gui::SbPart::Fixed(gui::dpi_x(225)),
        ],
    );

    let app = Win32App {
        wnd,
        target_edit,
        btn_browse,
        btn_load,
        browser_combo,
        btn_open_browser,
        profile_combo,
        chk_decrypt,
        keys_edit,
        btn_extract,
        btn_export,
        btn_custody,
        tab,
        tab_pages,
        cache_pg,
        overview_pg,
        findings_pg,
        timeline_pg,
        history_pg,
        creds_pg,
        ext_pg,
        sess_pg,
        browser_pg,
        status_bar,
        state,
        suppress_sync: Arc::new(AtomicBool::new(false)),
    };

    app.register_events();
    app.wnd
        .run_main(None)
        .map_err(|e| anyhow::anyhow!("Win32 message loop error: {e}"))?;
    Ok(())
}

impl Win32App {
    fn select_tab_index(&self, idx: u32) {
        unsafe {
            self.tab.hwnd().SendMessage(msg::TcmSetCurSel { index: idx });
        }
        self.layout_active_tab_page(idx);
    }

    fn layout_active_tab_page(&self, active_idx: u32) {
        for (i, pg) in self.tab_pages.iter().enumerate() {
            if i as u32 != active_idx {
                let _ = pg.hwnd().ShowWindow(co::SW::HIDE);
            }
        }
        if let Some(pg) = self.tab_pages.get(active_idx as usize)
            && let Ok(tab_rc) = self.tab.hwnd().GetWindowRect()
            && let Ok(mut rc) = self.wnd.hwnd().ScreenToClientRc(tab_rc)
        {
            unsafe {
                self.tab.hwnd().SendMessage(msg::TcmAdjustRect {
                    display_rect: false,
                    rect: &mut rc,
                });
            }
            let _ = pg.hwnd().SetWindowPos(
                w::HwndPlace::None,
                w::POINT::with(rc.left, rc.top),
                w::SIZE::with((rc.right - rc.left).max(10), (rc.bottom - rc.top).max(10)),
                co::SWP::NOZORDER | co::SWP::SHOWWINDOW,
            );
        }
    }

    fn sync_controls_to_state(&self) {
        if self.suppress_sync.load(Ordering::SeqCst) {
            return;
        }
        let mut st = self.state.lock().unwrap();
        st.path_input = self.target_edit.text().unwrap_or_default();
        st.decrypt_enabled = self.chk_decrypt.is_checked();
        st.keys_text = self.keys_edit.text().unwrap_or_default();
        st.quick_filter = self.cache_pg.filter_edit.text().unwrap_or_default();
        st.content_cat = ContentQuickCat::from_index(self.cache_pg.cat_combo.items().selected_index());
        st.hide_zero_length = self.cache_pg.chk_no_zero.is_checked();
    }

    fn refresh_status_bar(&self, st: &Win32State) {
        let _ = self.status_bar.parts().get(0).set_text(&st.status_message);

        let prof_seg = match (&st.report, st.selected_profile_idx) {
            (Some(r), Some(idx)) => r.profiles.get(idx).map(|p| p.profile_name.as_str()).unwrap_or("All"),
            (Some(_), None) => "All Profiles",
            (None, _) => "No Profile Loaded",
        };
        let _ = self.status_bar.parts().get(1).set_text(prof_seg);

        let vis_bytes: u64 = st
            .filtered_indices
            .iter()
            .filter_map(|&idx| st.all_cache_entries.get(idx))
            .map(|e| e.file_size as u64)
            .sum();
        let cache_seg = format!(
            "Cache: {}/{} ({})",
            st.filtered_indices.len(),
            st.all_cache_entries.len(),
            format_bytes(vis_bytes)
        );
        let _ = self.status_bar.parts().get(2).set_text(&cache_seg);
        let _ = self.status_bar.parts().get(3).set_text("100% Pure Rust - Native Win32");
    }

    fn refresh_profile_combo(&self) {
        let st = self.state.lock().unwrap();
        self.profile_combo.items().delete_all();
        if let Some(rep) = &st.report {
            let mut items = vec![format!("All Profiles ({})", rep.summary.total_cache_entries)];
            for p in &rep.profiles {
                items.push(format!("{} ({})", p.profile_name, p.cache_entries.len()));
            }
            let _ = self.profile_combo.items().add(&items);
            let sel = st.selected_profile_idx.map(|i| (i + 1) as u32).unwrap_or(0);
            self.profile_combo.items().select(Some(sel));
        } else {
            let _ = self.profile_combo.items().add(&["(No target loaded)"]);
            self.profile_combo.items().select(Some(0));
        }
    }

    fn refresh_cache_list_and_preview(&self) {
        let st = self.state.lock().unwrap();
        self.cache_pg.list.set_redraw(false);
        let _ = self.cache_pg.list.items().delete_all();
        for &raw_idx in st.filtered_indices.iter().take(MAX_WIN32_LIST_ROWS) {
            let e = &st.all_cache_entries[raw_idx];
            let ct = e.content_type.as_deref().unwrap_or("");
            let det = e.detected_content_type.as_deref().unwrap_or("");
            let ext = e.detected_extension.as_deref().unwrap_or("");
            let sz = if e.file_size > 1024 {
                format!("{} ({})", e.file_size, format_bytes(e.file_size as u64))
            } else {
                e.file_size.to_string()
            };
            let mismatch = if e.mime_mismatch { "YES" } else { "No" };
            let accessed = format_local_opt(e.last_accessed, st.show_millis);
            let _ = self.cache_pg.list.items().add(
                &[
                    &e.url,
                    ct,
                    det,
                    ext,
                    &sz,
                    mismatch,
                    &e.server_response,
                    &accessed,
                    &e.cache_name,
                ],
                None,
                (),
            );
        }
        self.cache_pg.list.set_redraw(true);

        if let Some(entry) = st.selected_cache_entry() {
            let txt = st.format_entry_preview(entry);
            let _ = self.cache_pg.inspector.set_text(&txt);
        } else if st.filtered_indices.is_empty() {
            let _ = self
                .cache_pg
                .inspector
                .set_text("No cache entries match the active filter (or no cache directory loaded yet).");
        } else {
            let _ = self.cache_pg.inspector.set_text(
                "Select a cache entry in the table to inspect HTTP headers, text/hex payload, or TLS/X.509 metadata.",
            );
        }
        self.refresh_status_bar(&st);
    }

    fn refresh_overview_tab(&self) {
        let st = self.state.lock().unwrap();
        self.overview_pg.domains_list.set_redraw(false);
        let _ = self.overview_pg.domains_list.items().delete_all();

        let Some(rep) = &st.report else {
            let _ = self
                .overview_pg
                .summary_edit
                .set_text("Open a Chrome User Data or Profile folder to inspect overview & generate forensic reports.");
            self.overview_pg.domains_list.set_redraw(true);
            return;
        };

        let s = &rep.summary;
        let ls = &rep.local_state;
        let mut lines = vec![
            format!("Target Path : {} ({:?})", rep.target_path, rep.target_kind),
            format!(
                "Profiles    : {} | HTTP Cache: {} entries ({})",
                s.profile_count,
                s.total_cache_entries,
                format_bytes(s.total_cache_bytes)
            ),
            format!(
                "History     : {} URLs / {} visits / {} downloads",
                s.total_history_urls, s.total_history_visits, s.total_downloads
            ),
            format!(
                "Creds/Store : {} logins | {} cookies | {} autofill | {} storage keys",
                s.total_logins, s.total_cookies, s.total_autofill_entries, s.total_local_storage_keys
            ),
            format!(
                "Other       : {} bookmarks | {} extensions | {}/{} open/closed tabs | {} timeline | {} findings",
                s.total_bookmarks,
                s.total_extensions,
                s.total_open_tabs,
                s.total_closed_tabs,
                s.total_timeline_events,
                s.total_findings
            ),
            format!(
                "Local State : Chrome {} | OS Crypt Key Present: {} ({}) | Country: {} | Policies: {}",
                ls.chrome_version.as_deref().unwrap_or("Unknown"),
                ls.os_crypt_encrypted_key_present,
                ls.os_crypt_key_prefix.as_deref().unwrap_or("-"),
                ls.variations_country.as_deref().unwrap_or("-"),
                ls.policy_count
            ),
        ];
        if let Some(portal) = &ls.os_crypt_portal_info {
            lines.push(format!("OS Crypt Portal: {portal}"));
        }
        for pm in &ls.profile_summaries {
            lines.push(format!(
                "  • {} — Name: {} | Email: {} | Ephemeral: {} | Active: {}",
                pm.dir_name,
                pm.name.as_deref().unwrap_or("-"),
                pm.user_name.as_deref().unwrap_or("-"),
                pm.is_ephemeral,
                format_local_opt(pm.active_time, false),
            ));
        }
        let _ = self.overview_pg.summary_edit.set_text(&lines.join("\r\n"));

        for d in rep.top_domains.iter().take(100) {
            let _ = self.overview_pg.domains_list.items().add(
                &[
                    &d.domain,
                    &d.history_visits.to_string(),
                    &d.cache_items.to_string(),
                    &format_bytes(d.cache_bytes),
                    &d.cookies.to_string(),
                ],
                None,
                (),
            );
        }
        self.overview_pg.domains_list.set_redraw(true);
    }

    fn refresh_findings_tab(&self) {
        let mut st = self.state.lock().unwrap();
        st.finding_sev_filter = match self.findings_pg.sev_combo.items().selected_index() {
            Some(1) => Some(FindingSeverity::Critical),
            Some(2) => Some(FindingSeverity::High),
            Some(3) => Some(FindingSeverity::Medium),
            Some(4) => Some(FindingSeverity::Low),
            Some(5) => Some(FindingSeverity::Info),
            _ => None,
        };
        st.findings_search = self.findings_pg.search_edit.text().unwrap_or_default();

        self.findings_pg.list.set_redraw(false);
        let _ = self.findings_pg.list.items().delete_all();

        let Some(rep) = &st.report else {
            let _ = self.findings_pg.evidence_edit.set_text("No User Data report loaded.");
            self.findings_pg.list.set_redraw(true);
            return;
        };

        let sel_pname = st
            .selected_profile_idx
            .and_then(|idx| rep.profiles.get(idx))
            .map(|p| p.profile_name.as_str());
        let q = st.findings_search.trim().to_ascii_lowercase();
        let mut evidence_lines = Vec::new();

        for f in &rep.findings {
            if let Some(sp) = sel_pname
                && f.profile != sp
            {
                continue;
            }
            if let Some(sv) = st.finding_sev_filter
                && f.severity != sv
            {
                continue;
            }
            if !q.is_empty()
                && !f.title.to_ascii_lowercase().contains(&q)
                && !f.summary.to_ascii_lowercase().contains(&q)
                && !f.category.to_ascii_lowercase().contains(&q)
                && !f.evidence.iter().any(|e| e.to_ascii_lowercase().contains(&q))
            {
                continue;
            }
            let sev = f.severity.as_str().to_ascii_uppercase();
            let _ = self
                .findings_pg
                .list
                .items()
                .add(&[&sev, &f.profile, &f.category, &f.title, &f.summary], None, ());
            if !f.evidence.is_empty() && evidence_lines.len() < 400 {
                evidence_lines.push(format!("[{sev}] {} ({}):", f.title, f.profile));
                for ev in &f.evidence {
                    evidence_lines.push(format!("  - {ev}"));
                }
            }
        }
        self.findings_pg.list.set_redraw(true);
        let ev_txt = if evidence_lines.is_empty() {
            "No matching forensic findings or evidence items.".to_string()
        } else {
            evidence_lines.join("\r\n")
        };
        let _ = self.findings_pg.evidence_edit.set_text(&ev_txt);
    }

    fn refresh_timeline_tab(&self) {
        let mut st = self.state.lock().unwrap();
        let cat = match self.timeline_pg.mode_combo.items().selected_index() {
            Some(1) => "History",
            Some(2) => "Download",
            Some(3) => "Cache",
            Some(4) => "Cookie",
            Some(5) => "Credential",
            Some(6) => "Bookmark",
            Some(7) => "Extension",
            Some(8) => "Session",
            _ => "All",
        };
        st.timeline_cat_filter = cat.to_string();
        st.timeline_search = self.timeline_pg.search_edit.text().unwrap_or_default();

        self.timeline_pg.list.set_redraw(false);
        let _ = self.timeline_pg.list.items().delete_all();

        let Some(rep) = &st.report else {
            self.timeline_pg.list.set_redraw(true);
            return;
        };

        let sel_pname = st
            .selected_profile_idx
            .and_then(|idx| rep.profiles.get(idx))
            .map(|p| p.profile_name.as_str());
        let q = st.timeline_search.trim().to_ascii_lowercase();
        let mut shown = 0usize;

        for ev in &rep.timeline {
            if let Some(sp) = sel_pname
                && ev.profile != sp
            {
                continue;
            }
            if st.timeline_cat_filter != "All" && ev.category != st.timeline_cat_filter {
                continue;
            }
            if !q.is_empty()
                && !ev.target.to_ascii_lowercase().contains(&q)
                && !ev.details.to_ascii_lowercase().contains(&q)
                && !ev.event_type.to_ascii_lowercase().contains(&q)
            {
                continue;
            }
            let ts = format_local_opt(Some(ev.timestamp), st.show_millis);
            let _ = self.timeline_pg.list.items().add(
                &[
                    &ts,
                    &ev.profile,
                    &ev.category,
                    &ev.event_type,
                    &ev.target,
                    &ev.details,
                    &ev.source_artifact,
                ],
                None,
                (),
            );
            shown += 1;
            if shown >= MAX_WIN32_LIST_ROWS {
                break;
            }
        }
        self.timeline_pg.list.set_redraw(true);
        let _ = self.timeline_pg.info_lbl.hwnd().SetWindowText(&format!(
            "Displayed {shown} timeline event(s) (total {}).",
            rep.timeline.len()
        ));
    }

    fn refresh_history_tab(&self) {
        let mut st = self.state.lock().unwrap();
        st.history_sub = HistorySubTab::from_index(self.history_pg.mode_combo.items().selected_index());
        st.history_search = self.history_pg.search_edit.text().unwrap_or_default();

        self.history_pg.list.set_redraw(false);
        let _ = self.history_pg.list.items().delete_all();

        let profiles = st.visible_profiles();
        if profiles.is_empty() {
            self.history_pg.list.set_redraw(true);
            return;
        }

        let mut summary_parts = Vec::new();
        for (_, p) in &profiles {
            let di = &p.history.deletion_indicators;
            summary_parts.push(format!(
                "[{}] URLs: {} (seq {}, est.del: {}) | Visits: {} (seq {}, est.del: {})",
                p.profile_name,
                di.urls_row_count,
                di.urls_sqlite_seq,
                di.urls_estimated_deleted,
                di.visits_row_count,
                di.visits_sqlite_seq,
                di.visits_estimated_deleted
            ));
        }
        let _ = self
            .history_pg
            .info_lbl
            .hwnd()
            .SetWindowText(&summary_parts.join("   |   "));

        let q = st.history_search.trim().to_ascii_lowercase();
        let mut count = 0usize;

        match st.history_sub {
            HistorySubTab::Urls => {
                for (_, p) in &profiles {
                    for u in &p.history.urls {
                        if !q.is_empty()
                            && !u.url.to_ascii_lowercase().contains(&q)
                            && !u.title.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let ts = format_local_opt(u.last_visit_time, false);
                        let counts = format!("{} visits / {} typed", u.visit_count, u.typed_count);
                        let _ = self.history_pg.list.items().add(
                            &[&p.profile_name, &ts, &counts, "URL Record", &u.title, &u.url],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
            HistorySubTab::Visits => {
                for (_, p) in &profiles {
                    for v in &p.history.visits {
                        if !q.is_empty()
                            && !v.url.to_ascii_lowercase().contains(&q)
                            && !v.title.to_ascii_lowercase().contains(&q)
                            && !v.transition_core.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let ts = format_local_opt(v.visit_time, false);
                        let dur = format!("{} ms", v.visit_duration_ms);
                        let trans = if v.transition_qualifiers.is_empty() {
                            v.transition_core.clone()
                        } else {
                            format!("{} ({})", v.transition_core, v.transition_qualifiers.join(", "))
                        };
                        let _ = self.history_pg.list.items().add(
                            &[&p.profile_name, &ts, &dur, &trans, &v.title, &v.url],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
            HistorySubTab::Downloads => {
                for (_, p) in &profiles {
                    for d in &p.history.downloads {
                        let urls = d.url_chain.join(" -> ");
                        if !q.is_empty()
                            && !d.target_path.to_ascii_lowercase().contains(&q)
                            && !urls.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let ts = format_local_opt(d.start_time, false);
                        let bytes = format_bytes(d.total_bytes.max(d.received_bytes).max(0) as u64);
                        let state = format!("{} ({bytes})", d.state);
                        let _ = self.history_pg.list.items().add(
                            &[&p.profile_name, &ts, &state, &d.danger_type, &d.target_path, &urls],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
            HistorySubTab::SearchTerms => {
                for (_, p) in &profiles {
                    for s in &p.history.search_terms {
                        if !q.is_empty()
                            && !s.term.to_ascii_lowercase().contains(&q)
                            && !s.url.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let ts = format_local_opt(s.last_visit_time, false);
                        let _ = self.history_pg.list.items().add(
                            &[
                                &p.profile_name,
                                &ts,
                                "Search",
                                "Omnibox Query",
                                &s.term,
                                s.url.as_deref().unwrap_or(""),
                            ],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
        }
        self.history_pg.list.set_redraw(true);
    }

    fn refresh_creds_tab(&self) {
        let mut st = self.state.lock().unwrap();
        st.cred_sub = CredSubTab::from_index(self.creds_pg.mode_combo.items().selected_index());
        st.cred_search = self.creds_pg.search_edit.text().unwrap_or_default();

        self.creds_pg.list.set_redraw(false);
        let _ = self.creds_pg.list.items().delete_all();

        let profiles = st.visible_profiles();
        if profiles.is_empty() {
            self.creds_pg.list.set_redraw(true);
            return;
        }

        let q = st.cred_search.trim().to_ascii_lowercase();
        let mut count = 0usize;

        match st.cred_sub {
            CredSubTab::Logins => {
                for (_, p) in &profiles {
                    for l in &p.logins {
                        if !q.is_empty()
                            && !l.origin_url.to_ascii_lowercase().contains(&q)
                            && !l.username_value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let pw = l
                            .password_decrypted
                            .clone()
                            .unwrap_or_else(|| format!("[Encrypted {} B]", l.password_encrypted_len));
                        let meta = format!(
                            "Uses: {} | Last: {} | {}",
                            l.times_used,
                            format_local_opt(l.date_last_used, false),
                            l.insecure_issues.join(", ")
                        );
                        let _ = self.creds_pg.list.items().add(
                            &[
                                &p.profile_name,
                                &l.origin_url,
                                &l.username_value,
                                l.encryption_scheme.as_str(),
                                &pw,
                                &meta,
                            ],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            CredSubTab::Cookies => {
                for (_, p) in &profiles {
                    for c in &p.cookies {
                        if !q.is_empty()
                            && !c.host_key.to_ascii_lowercase().contains(&q)
                            && !c.name.to_ascii_lowercase().contains(&q)
                            && !c.value.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let val = c
                            .value
                            .clone()
                            .unwrap_or_else(|| format!("[Encrypted {} B]", c.encrypted_len));
                        let flags = format!(
                            "{} (Sec:{} Http:{})",
                            c.encryption_scheme.as_str(),
                            if c.is_secure { "Y" } else { "N" },
                            if c.is_httponly { "Y" } else { "N" }
                        );
                        let meta = format!("{} | Exp: {}", c.samesite, format_local_opt(c.expires_utc, false));
                        let _ = self.creds_pg.list.items().add(
                            &[&p.profile_name, &c.host_key, &c.name, &flags, &val, &meta],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            CredSubTab::Autofill => {
                for (_, p) in &profiles {
                    for a in &p.web_data.autofill {
                        if !q.is_empty()
                            && !a.name.to_ascii_lowercase().contains(&q)
                            && !a.value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let meta = format!(
                            "Created: {} | Last: {}",
                            format_local_opt(a.date_created, false),
                            format_local_opt(a.date_last_used, false)
                        );
                        let _ = self.creds_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "Autofill",
                                &a.name,
                                &format!("Count: {}", a.count),
                                &a.value,
                                &meta,
                            ],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            CredSubTab::AddressesCards => {
                for (_, p) in &profiles {
                    for a in &p.web_data.addresses {
                        let addr = format!("{} {} {} {}", a.street_address, a.city, a.state, a.zipcode);
                        let _ = self.creds_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "Address",
                                &a.full_name,
                                &a.email,
                                &addr,
                                &format!("{} (uses: {})", a.phone, a.use_count),
                            ],
                            None,
                            (),
                        );
                    }
                    for c in &p.web_data.credit_cards {
                        let _ = self.creds_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "Payment Card",
                                &c.name_on_card,
                                &c.network,
                                &format!("****{}", c.last_four),
                                &format!(
                                    "Exp {}/{} (uses: {})",
                                    c.expiration_month, c.expiration_year, c.use_count
                                ),
                            ],
                            None,
                            (),
                        );
                    }
                }
            }
        }
        self.creds_pg.list.set_redraw(true);
    }

    fn refresh_extensions_tab(&self) {
        let mut st = self.state.lock().unwrap();
        st.ext_show_bookmarks = self.ext_pg.mode_combo.items().selected_index() == Some(1);
        st.ext_search = self.ext_pg.search_edit.text().unwrap_or_default();

        self.ext_pg.list.set_redraw(false);
        let _ = self.ext_pg.list.items().delete_all();

        let profiles = st.visible_profiles();
        let q = st.ext_search.trim().to_ascii_lowercase();
        let mut count = 0usize;

        if !st.ext_show_bookmarks {
            for (_, p) in &profiles {
                for ext in &p.extensions {
                    if !q.is_empty()
                        && !ext.name.to_ascii_lowercase().contains(&q)
                        && !ext.id.to_ascii_lowercase().contains(&q)
                        && !ext.risk_flags.iter().any(|r| r.to_ascii_lowercase().contains(&q))
                    {
                        continue;
                    }
                    let ver = format!("v{} ({})", ext.version, ext.location);
                    let risk_perm = if ext.risk_flags.is_empty() {
                        ext.permissions.join(", ")
                    } else {
                        format!("RISK: {} | {}", ext.risk_flags.join(", "), ext.permissions.join(", "))
                    };
                    let _ = self.ext_pg.list.items().add(
                        &[&p.profile_name, &ext.name, &ver, &ext.id, &risk_perm],
                        None,
                        (),
                    );
                    count += 1;
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
        } else {
            for (_, p) in &profiles {
                for b in &p.bookmarks {
                    if !q.is_empty()
                        && !b.name.to_ascii_lowercase().contains(&q)
                        && !b.url.to_ascii_lowercase().contains(&q)
                        && !b.folder_path.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    let _ = self.ext_pg.list.items().add(
                        &[&p.profile_name, &b.name, "Bookmark", &b.url, &b.folder_path],
                        None,
                        (),
                    );
                    count += 1;
                    if count >= MAX_WIN32_LIST_ROWS {
                        break;
                    }
                }
            }
        }
        self.ext_pg.list.set_redraw(true);
    }

    fn refresh_sessions_tab(&self) {
        let mut st = self.state.lock().unwrap();
        st.sess_sub = SessionSubTab::from_index(self.sess_pg.mode_combo.items().selected_index());
        st.sess_search = self.sess_pg.search_edit.text().unwrap_or_default();

        self.sess_pg.list.set_redraw(false);
        let _ = self.sess_pg.list.items().delete_all();

        let profiles = st.visible_profiles();
        let q = st.sess_search.trim().to_ascii_lowercase();
        let mut count = 0usize;

        match st.sess_sub {
            SessionSubTab::Tabs => {
                for (_, p) in &profiles {
                    for t in p.sessions.open_tabs.iter().chain(p.sessions.closed_tabs.iter()) {
                        if !q.is_empty()
                            && !t.current_url.to_ascii_lowercase().contains(&q)
                            && !t.current_title.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let state_tag = if t.is_closed { "CLOSED" } else { "OPEN" };
                        let _ = self.sess_pg.list.items().add(
                            &[
                                &p.profile_name,
                                &t.source_file,
                                &format!("{state_tag} Tab #{}", t.tab_id),
                                &t.current_title,
                                &format!("{} ({} navs)", t.current_url, t.navigations.len()),
                            ],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            SessionSubTab::LocalStorage => {
                for (_, p) in &profiles {
                    for kv in &p.storage.local_storage {
                        if !q.is_empty()
                            && !kv.origin.to_ascii_lowercase().contains(&q)
                            && !kv.key.to_ascii_lowercase().contains(&q)
                            && !kv.value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let _ = self.sess_pg.list.items().add(
                            &[&p.profile_name, &kv.origin, &kv.key, &kv.value, "LocalStorage"],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            SessionSubTab::SessionStorage => {
                for (_, p) in &profiles {
                    for kv in &p.storage.session_storage {
                        if !q.is_empty()
                            && !kv.origin.to_ascii_lowercase().contains(&q)
                            && !kv.key.to_ascii_lowercase().contains(&q)
                            && !kv.value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let _ = self.sess_pg.list.items().add(
                            &[&p.profile_name, &kv.origin, &kv.key, &kv.value, "SessionStorage"],
                            None,
                            (),
                        );
                        count += 1;
                        if count >= MAX_WIN32_LIST_ROWS {
                            break;
                        }
                    }
                }
            }
            SessionSubTab::MiscInventory => {
                for (_, p) in &profiles {
                    for idb in &p.storage.indexed_db_origins {
                        let _ = self.sess_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "IndexedDB",
                                &idb.origin_dir,
                                &format!("{} files", idb.file_count),
                                &format_bytes(idb.total_bytes),
                            ],
                            None,
                            (),
                        );
                    }
                    for ts in &p.storage.top_sites {
                        let _ = self.sess_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "TopSites",
                                &format!("Rank #{}", ts.rank),
                                &ts.title,
                                &ts.url,
                            ],
                            None,
                            (),
                        );
                    }
                    for f in p.file_inventory.iter().take(500) {
                        if !q.is_empty()
                            && !f.relative_path.to_ascii_lowercase().contains(&q)
                            && !f.category.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        let _ = self.sess_pg.list.items().add(
                            &[
                                &p.profile_name,
                                "FileInventory",
                                &f.category,
                                &f.relative_path,
                                &format_bytes(f.size_bytes),
                            ],
                            None,
                            (),
                        );
                    }
                }
            }
        }
        self.sess_pg.list.set_redraw(true);
    }

    fn refresh_all_views(&self) {
        self.refresh_profile_combo();
        self.refresh_cache_list_and_preview();
        self.refresh_overview_tab();
        self.refresh_findings_tab();
        self.refresh_timeline_tab();
        self.refresh_history_tab();
        self.refresh_creds_tab();
        self.refresh_extensions_tab();
        self.refresh_sessions_tab();
        if self.tab.items().selected().map(|i| i.index()).unwrap_or(0) == 8 {
            self.refresh_browser_tools_tab();
        }
    }

    fn refresh_browser_tools_tab(&self) {
        let tool_idx = self.browser_pg.tool_combo.items().selected_index().unwrap_or(0) as usize;
        let filter_txt = self.browser_pg.filter_edit.text().unwrap_or_default();

        let (status_msg, cols, row_cells) = {
            let mut st = self.state.lock().unwrap();
            st.ensure_browser_grid_loaded();
            if st.browser_grid.active_tool_idx != tool_idx {
                st.browser_grid.select_tool(tool_idx);
            }
            if st.browser_grid.filter_text != filter_txt {
                st.browser_grid.set_filter(filter_txt);
            } else {
                st.browser_grid.refresh();
            }
            let cols: Vec<(String, i32)> = st
                .browser_grid
                .columns()
                .iter()
                .map(|c| (c.label.clone(), (c.width_hint as i32).max(70)))
                .collect();
            let col_count = cols.len();
            let max_rows = st.browser_grid.row_count().min(MAX_WIN32_LIST_ROWS);
            let mut rows_out = Vec::with_capacity(max_rows);
            for r in 0..max_rows {
                let mut cells = Vec::with_capacity(col_count);
                for c in 0..col_count {
                    cells.push(st.browser_grid.cell_text(r, c));
                }
                rows_out.push(cells);
            }
            (st.browser_grid.status_message.clone(), cols, rows_out)
        };

        let _ = self.browser_pg.info_lbl.hwnd().SetWindowText(&status_msg);
        self.browser_pg.list.set_redraw(false);
        let _ = self.browser_pg.list.items().delete_all();
        loop {
            let count = self.browser_pg.list.cols().count().unwrap_or(0);
            if count == 0 {
                break;
            }
            if unsafe {
                self.browser_pg
                    .list
                    .hwnd()
                    .SendMessage(msg::LvmDeleteColumn { index: 0 })
            }
            .is_err()
            {
                break;
            }
        }
        for (label, width) in &cols {
            let _ = self.browser_pg.list.cols().add(label, gui::dpi_x(*width));
        }
        for row in &row_cells {
            let refs: Vec<&str> = row.iter().map(String::as_str).collect();
            let _ = self.browser_pg.list.items().add(&refs, None, ());
        }
        self.browser_pg.list.set_redraw(true);
        let _ = self
            .browser_pg
            .inspector
            .set_text("Select a row to inspect details and raw bytes.");
    }

    fn trigger_export_browser_tool(&self) {
        if let Ok(Some(dest)) = pick_save_file(
            self.wnd.hwnd(),
            "Export Multi-Browser Tool Table",
            "chrome2rust_tool_export.csv",
            "csv",
            &[("CSV (*.csv)", "*.csv")],
        ) {
            let msg = {
                let mut st = self.state.lock().unwrap();
                st.ensure_browser_grid_loaded();
                match st.browser_grid.export_to_path(&dest, guap_export::ExportFormat::Csv) {
                    Ok(m) => format!(
                        "Exported {} rows to {} (SHA-256 Merkle root: {})",
                        st.browser_grid.row_count(),
                        dest.display(),
                        m.merkle_root_sha256
                    ),
                    Err(e) => format!("Export error: {e}"),
                }
            };
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&msg, "Multi-Browser Tool Export", co::MB::ICONINFORMATION);
        }
    }

    fn trigger_browse_and_load(&self) {
        let initial = self.state.lock().unwrap().path_input.clone();
        if let Ok(Some(folder)) = pick_folder(
            self.wnd.hwnd(),
            "Select Chrome User Data, Profile, or Cache Folder",
            Some(&initial),
        ) {
            self.start_load_path(folder);
        }
    }

    fn start_load_path(&self, path: PathBuf) {
        {
            let mut st = self.state.lock().unwrap();
            st.decrypt_enabled = self.chk_decrypt.is_checked();
            st.keys_text = self.keys_edit.text().unwrap_or_default();
            st.start_load(path);
            self.suppress_sync.store(true, Ordering::SeqCst);
            let _ = self.target_edit.set_text(&st.path_input);
            self.suppress_sync.store(false, Ordering::SeqCst);
            self.refresh_status_bar(&st);
        }
    }

    fn load_selected_browser(&self) {
        let idx = self.browser_combo.items().selected_index().unwrap_or(0) as usize;
        let target = {
            let st = self.state.lock().unwrap();
            st.discovered_browsers.get(idx).and_then(|b| {
                if b.user_data_dir.is_dir() {
                    Some(b.user_data_dir.clone())
                } else {
                    b.cache_root_dir.clone()
                }
            })
        };
        if let Some(dir) = target {
            self.start_load_path(dir);
        }
    }

    fn selected_cache_row_indices(&self) -> Vec<usize> {
        self.cache_pg
            .list
            .items()
            .iter_selected()
            .map(|it| it.index() as usize)
            .collect()
    }

    fn trigger_extract_cache(&self) {
        let sel = self.selected_cache_row_indices();
        let initial = self.state.lock().unwrap().path_input.clone();
        if let Ok(Some(out_dir)) = pick_folder(
            self.wnd.hwnd(),
            "Select Destination Directory for Extracted Cache Payloads",
            Some(&initial),
        ) {
            let msg = {
                let mut st = self.state.lock().unwrap();
                let entries: Vec<_> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .cloned()
                    .collect();
                let refs: Vec<_> = entries.iter().collect();
                let res = st.extract_entries(&refs, &out_dir);
                self.refresh_status_bar(&st);
                res
            };
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&msg, "Cache Extraction", co::MB::ICONINFORMATION);
        }
    }

    fn trigger_export_cache(&self, fmt: ExportFormat, default_name: &str, ext: &str, filter: (&str, &str)) {
        let sel = self.selected_cache_row_indices();
        if let Ok(Some(dest)) = pick_save_file(
            self.wnd.hwnd(),
            "Export Chrome Cache Table",
            default_name,
            ext,
            &[filter],
        ) {
            let msg = {
                let mut st = self.state.lock().unwrap();
                let entries: Vec<_> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .cloned()
                    .collect();
                let res = st.export_table(&entries, &dest, fmt);
                self.refresh_status_bar(&st);
                res
            };
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&msg, "Cache Table Export", co::MB::ICONINFORMATION);
        }
    }

    fn trigger_export_any(&self) {
        let sel = self.selected_cache_row_indices();
        let filters = [
            ("CSV (*.csv)", "*.csv"),
            ("TSV (*.tsv)", "*.tsv"),
            ("JSON (*.json)", "*.json"),
            ("HTML Table (*.html)", "*.html"),
            ("XML (*.xml)", "*.xml"),
            ("Tabular Text (*.txt)", "*.txt"),
        ];
        if let Ok(Some(dest)) = pick_save_file(
            self.wnd.hwnd(),
            "Export Chrome Cache Table",
            "chrome_cache_export.csv",
            "csv",
            &filters,
        ) {
            let ext = dest
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let fmt = match ext.as_str() {
                "tsv" => ExportFormat::Tab,
                "json" => ExportFormat::Json,
                "html" | "htm" => ExportFormat::HtmlHorizontal,
                "xml" => ExportFormat::Xml,
                "txt" => ExportFormat::Tabular,
                _ => ExportFormat::Csv,
            };
            let msg = {
                let mut st = self.state.lock().unwrap();
                let entries: Vec<_> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .cloned()
                    .collect();
                let res = st.export_table(&entries, &dest, fmt);
                self.refresh_status_bar(&st);
                res
            };
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&msg, "Cache Table Export", co::MB::ICONINFORMATION);
        }
    }

    fn trigger_export_urls(&self) {
        let sel = self.selected_cache_row_indices();
        if let Ok(Some(dest)) = pick_save_file(
            self.wnd.hwnd(),
            "Export Chrome Cache URLs",
            "chrome_cache_urls.txt",
            "txt",
            &[("URLs Text File (*.txt)", "*.txt")],
        ) {
            let msg = {
                let mut st = self.state.lock().unwrap();
                let urls: Vec<String> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .map(|e| e.url.clone())
                    .collect();
                match std::fs::write(&dest, urls.join("\n")) {
                    Ok(()) => {
                        let m = format!("Exported {} URL(s) to {}", urls.len(), dest.display());
                        st.status_message = m.clone();
                        self.refresh_status_bar(&st);
                        m
                    }
                    Err(e) => {
                        let m = format!("Write error: {e}");
                        st.status_message = m.clone();
                        self.refresh_status_bar(&st);
                        m
                    }
                }
            };
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&msg, "Export Cache URLs", co::MB::ICONINFORMATION);
        }
    }

    fn trigger_report(&self, fmt: ReportFormat) {
        if self.state.lock().unwrap().report.is_none() {
            let _ = self.wnd.hwnd().MessageBox(
                "Load a Chrome User Data or Profile directory before generating reports.",
                "No Profile Loaded",
                co::MB::ICONINFORMATION,
            );
            return;
        }
        let target = if fmt == ReportFormat::All {
            pick_folder(
                self.wnd.hwnd(),
                "Select Directory for Full Report Bundle (HTML + JSON + Markdown)",
                None,
            )
            .ok()
            .flatten()
        } else {
            let (def, ext, filter) = match fmt {
                ReportFormat::Html => ("chrome2rust_forensic_report.html", "html", ("HTML Report", "*.html")),
                ReportFormat::Json => ("chrome2rust_forensic_report.json", "json", ("JSON Report", "*.json")),
                ReportFormat::Markdown => ("chrome2rust_forensic_report.md", "md", ("Markdown Report", "*.md")),
                ReportFormat::All => unreachable!(),
            };
            pick_save_file(self.wnd.hwnd(), "Save Forensic Report", def, ext, &[filter])
                .ok()
                .flatten()
        };

        if let Some(dest) = target {
            let res = {
                let mut st = self.state.lock().unwrap();
                let r = st.write_forensic_report(&dest, fmt);
                self.refresh_status_bar(&st);
                r
            };
            match res {
                Ok(msg) => {
                    let _ = self
                        .wnd
                        .hwnd()
                        .MessageBox(&msg, "Forensic Report", co::MB::ICONINFORMATION);
                }
                Err(e) => {
                    let _ = self.wnd.hwnd().MessageBox(&e, "Report Error", co::MB::ICONERROR);
                }
            }
        }
    }

    fn trigger_custody_audit(&self) {
        let save_dest = pick_save_file(
            self.wnd.hwnd(),
            "Save Chain-of-Custody Manifest (Cancel to compute preview only)",
            "custody_manifest.json",
            "json",
            &[("JSON Manifest", "*.json"), ("CSV Manifest", "*.csv")],
        )
        .ok()
        .flatten();

        let res = {
            let mut st = self.state.lock().unwrap();
            let r = st.generate_custody(save_dest.as_deref());
            self.refresh_status_bar(&st);
            r
        };
        match res {
            Ok(m) => {
                let summary = format!(
                    "Chain-of-Custody Verification Complete\n\nArtifacts Hashed: {}\nTotal Bytes: {}\nMerkle Root (SHA-256):\n{}\n{}",
                    m.artifact_count,
                    format_bytes(m.total_bytes),
                    m.merkle_root_sha256,
                    save_dest
                        .as_ref()
                        .map(|p| format!("\nSaved to: {}", p.display()))
                        .unwrap_or_default()
                );
                let _ = self
                    .wnd
                    .hwnd()
                    .MessageBox(&summary, "SHA-256 Merkle Custody Audit", co::MB::ICONINFORMATION);
            }
            Err(e) => {
                let _ = self.wnd.hwnd().MessageBox(&e, "Custody Audit Error", co::MB::ICONERROR);
            }
        }
    }

    fn trigger_delete_selected(&self) {
        let sel = self.selected_cache_row_indices();
        if sel.is_empty() {
            let _ = self.wnd.hwnd().MessageBox(
                "Select one or more standalone cache entries first.",
                "No Selection",
                co::MB::ICONINFORMATION,
            );
            return;
        }
        let confirm = self.wnd.hwnd().MessageBox(
            &format!(
                "Delete {} selected standalone cache file(s) (*_0 or Blockfile f_xxxxxx)?\n(Entries inside shared Blockfile data_N containers are preserved.)",
                sel.len()
            ),
            "Confirm Standalone Cache File Deletion",
            co::MB::YESNO | co::MB::ICONWARNING,
        );
        if confirm != Ok(co::DLGID::YES) {
            return;
        }
        let (msg, reload_path) = {
            let mut st = self.state.lock().unwrap();
            let entries: Vec<_> = st
                .selected_or_filtered_entries(&sel, true)
                .into_iter()
                .cloned()
                .collect();
            let refs: Vec<_> = entries.iter().collect();
            let msg = st.delete_entries(&refs);
            let p = if st.path_input.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(st.path_input.trim()))
            };
            (msg, p)
        };
        let _ = self
            .wnd
            .hwnd()
            .MessageBox(&msg, "Delete Cache Files", co::MB::ICONINFORMATION);
        if let Some(p) = reload_path {
            self.start_load_path(p);
        }
    }

    fn register_events(&self) {
        let self2 = self.clone();
        self.wnd.on().wm_create(move |_| {
            {
                let st = self2.state.lock().unwrap();
                self2.suppress_sync.store(true, Ordering::SeqCst);
                let _ = self2.target_edit.set_text(&st.path_input);
                self2.chk_decrypt.set_check(st.decrypt_enabled);
                let _ = self2.keys_edit.set_text(&st.keys_text);
                self2.suppress_sync.store(false, Ordering::SeqCst);

                let browser_labels: Vec<String> = if st.discovered_browsers.is_empty() {
                    vec!["(No local Chromium browser detected)".to_string()]
                } else {
                    st.discovered_browsers
                        .iter()
                        .map(|b| format!("{} ({} profiles)", b.name, b.profiles.len()))
                        .collect()
                };
                let _ = self2.browser_combo.items().add(&browser_labels);
                self2.browser_combo.items().select(Some(0));
            }

            let _ = self2.wnd.hwnd().SetTimer(TIMER_POLL_ID, 100, None);
            self2.refresh_all_views();
            self2.layout_active_tab_page(0);

            let (init_path, init_pick) = {
                let mut st = self2.state.lock().unwrap();
                (st.initial_load_path.take(), st.initial_pick)
            };
            if let Some(p) = init_path {
                self2.start_load_path(p);
            } else if init_pick {
                self2.trigger_browse_and_load();
            }
            Ok(0)
        });

        let self2 = self.clone();
        self.wnd.on().wm_timer(TIMER_POLL_ID, move || {
            let outcome = {
                let mut st = self2.state.lock().unwrap();
                let out = st.poll_worker();
                if out.status_changed {
                    self2.refresh_status_bar(&st);
                }
                out
            };
            if outcome.finished {
                self2.refresh_all_views();
            }
            Ok(())
        });

        let self2 = self.clone();
        self.wnd.on().wm_destroy(move || {
            let _ = self2.wnd.hwnd().KillTimer(TIMER_POLL_ID);
            Ok(())
        });

        let self2 = self.clone();
        self.wnd.on().wm_size(move |_| {
            let idx = self2.tab.items().selected().map(|i| i.index()).unwrap_or(0);
            self2.layout_active_tab_page(idx);
            Ok(())
        });

        let self2 = self.clone();
        self.tab.on().tcn_sel_change(move || {
            let idx = self2.tab.items().selected().map(|i| i.index()).unwrap_or(0);
            self2.layout_active_tab_page(idx);
            if idx == 8 {
                self2.refresh_browser_tools_tab();
            }
            Ok(())
        });

        // Top toolbar controls
        {
            let app = self.clone();
            self.target_edit.on().en_change(move || {
                app.sync_controls_to_state();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.chk_decrypt.on().bn_clicked(move || {
                app.sync_controls_to_state();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.keys_edit.on().en_change(move || {
                app.sync_controls_to_state();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_browse.on().bn_clicked(move || {
                app.trigger_browse_and_load();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_load.on().bn_clicked(move || {
                app.sync_controls_to_state();
                let started = {
                    let mut st = app.state.lock().unwrap();
                    let ok = st.start_load_from_input();
                    app.refresh_status_bar(&st);
                    ok
                };
                if !started {
                    app.trigger_browse_and_load();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_open_browser.on().bn_clicked(move || {
                app.load_selected_browser();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.profile_combo.on().cbn_sel_change(move || {
                let sel = app.profile_combo.items().selected_index().unwrap_or(0);
                {
                    let mut st = app.state.lock().unwrap();
                    st.selected_profile_idx = if sel == 0 { None } else { Some((sel - 1) as usize) };
                    st.selected_filtered_pos = None;
                    st.rebuild_cache_view();
                }
                app.refresh_cache_list_and_preview();
                app.refresh_findings_tab();
                app.refresh_timeline_tab();
                app.refresh_history_tab();
                app.refresh_creds_tab();
                app.refresh_extensions_tab();
                app.refresh_sessions_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_extract.on().bn_clicked(move || {
                app.trigger_extract_cache();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_export.on().bn_clicked(move || {
                app.trigger_export_any();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_custody.on().bn_clicked(move || {
                app.trigger_custody_audit();
                Ok(())
            });
        }

        // Cache Inspector controls
        {
            let app = self.clone();
            self.cache_pg.filter_edit.on().en_change(move || {
                app.sync_controls_to_state();
                app.state.lock().unwrap().apply_cache_filter();
                app.refresh_cache_list_and_preview();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.cat_combo.on().cbn_sel_change(move || {
                app.sync_controls_to_state();
                app.state.lock().unwrap().apply_cache_filter();
                app.refresh_cache_list_and_preview();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.chk_no_zero.on().bn_clicked(move || {
                app.sync_controls_to_state();
                app.state.lock().unwrap().apply_cache_filter();
                app.refresh_cache_list_and_preview();
                Ok(())
            });
        }
        for (button, mode) in [
            (&self.cache_pg.btn_prev_auto, PreviewMode::Auto),
            (&self.cache_pg.btn_prev_hdr, PreviewMode::Headers),
            (&self.cache_pg.btn_prev_hex, PreviewMode::Hex),
        ] {
            let app = self.clone();
            button.on().bn_clicked(move || {
                app.state.lock().unwrap().preview_mode = mode;
                app.refresh_cache_list_and_preview();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.btn_copy_url.on().bn_clicked(move || {
                let sel = app.selected_cache_row_indices();
                let mut st = app.state.lock().unwrap();
                let urls: Vec<String> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .map(|e| e.url.clone())
                    .collect();
                if !urls.is_empty() && copy_to_clipboard(&urls.join("\n")) {
                    st.status_message = format!("Copied {} URL(s) to clipboard.", urls.len());
                    app.refresh_status_bar(&st);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.btn_copy_tsv.on().bn_clicked(move || {
                let sel = app.selected_cache_row_indices();
                let mut st = app.state.lock().unwrap();
                let entries: Vec<_> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .cloned()
                    .collect();
                if let Ok(tsv) = chrome2rust_cache::export::render_cache_export(
                    &entries,
                    ExportFormat::Tab,
                    &st.active_cache_columns,
                    true,
                    st.show_millis,
                ) && copy_to_clipboard(&tsv)
                {
                    st.status_message = format!("Copied {} cache row(s) as TSV.", entries.len());
                    app.refresh_status_bar(&st);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.btn_props.on().bn_clicked(move || {
                let msg = {
                    let st = app.state.lock().unwrap();
                    st.selected_cache_entry().map(|e| st.format_entry_properties(e))
                };
                if let Some(txt) = msg {
                    let _ = app
                        .wnd
                        .hwnd()
                        .MessageBox(&txt, "Cache Entry Properties", co::MB::ICONINFORMATION);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.btn_delete.on().bn_clicked(move || {
                app.trigger_delete_selected();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.list.on().lvn_item_changed(move |p| {
                if p.uNewState.has(co::LVIS::SELECTED) && p.iItem >= 0 {
                    let mut st = app.state.lock().unwrap();
                    st.selected_filtered_pos = Some(p.iItem as usize);
                    if let Some(entry) = st.selected_cache_entry() {
                        let txt = st.format_entry_preview(entry);
                        let _ = app.cache_pg.inspector.set_text(&txt);
                    }
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.list.on().nm_dbl_clk(move |_| {
                let msg = {
                    let st = app.state.lock().unwrap();
                    st.selected_cache_entry().map(|e| st.format_entry_properties(e))
                };
                if let Some(txt) = msg {
                    let _ = app
                        .wnd
                        .hwnd()
                        .MessageBox(&txt, "Cache Entry Properties", co::MB::ICONINFORMATION);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.cache_pg.list.on().lvn_column_click(move |p| {
                let field = match p.iSubItem {
                    0 => Some(CacheSortField::Url),
                    1 => Some(CacheSortField::ContentType),
                    2 => Some(CacheSortField::DetectedContentType),
                    3 => Some(CacheSortField::DetectedExtension),
                    4 => Some(CacheSortField::FileSize),
                    5 => Some(CacheSortField::MimeMismatch),
                    6 => Some(CacheSortField::ServerResponse),
                    7 => Some(CacheSortField::LastAccessed),
                    8 => Some(CacheSortField::CacheName),
                    _ => None,
                };
                if let Some(sf) = field {
                    let shift_held = w::GetAsyncKeyState(co::VK::SHIFT);
                    app.state.lock().unwrap().toggle_sort(sf, shift_held);
                    app.refresh_cache_list_and_preview();
                }
                Ok(())
            });
        }

        // Overview report buttons
        for (button, fmt) in [
            (&self.overview_pg.btn_html, ReportFormat::Html),
            (&self.overview_pg.btn_json, ReportFormat::Json),
            (&self.overview_pg.btn_md, ReportFormat::Markdown),
            (&self.overview_pg.btn_bundle, ReportFormat::All),
        ] {
            let app = self.clone();
            button.on().bn_clicked(move || {
                app.trigger_report(fmt);
                Ok(())
            });
        }

        // Findings, Timeline, History, Creds, Extensions, Sessions filter controls
        {
            let app = self.clone();
            self.findings_pg.sev_combo.on().cbn_sel_change(move || {
                app.refresh_findings_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.findings_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_findings_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.timeline_pg.mode_combo.on().cbn_sel_change(move || {
                app.refresh_timeline_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.timeline_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_timeline_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.history_pg.mode_combo.on().cbn_sel_change(move || {
                app.refresh_history_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.history_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_history_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.creds_pg.mode_combo.on().cbn_sel_change(move || {
                app.refresh_creds_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.creds_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_creds_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.ext_pg.mode_combo.on().cbn_sel_change(move || {
                app.refresh_extensions_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.ext_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_extensions_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.sess_pg.mode_combo.on().cbn_sel_change(move || {
                app.refresh_sessions_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.sess_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_sessions_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.browser_pg.tool_combo.on().cbn_sel_change(move || {
                app.refresh_browser_tools_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.browser_pg.btn_apply.on().bn_clicked(move || {
                app.refresh_browser_tools_tab();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.browser_pg.btn_export.on().bn_clicked(move || {
                app.trigger_export_browser_tool();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.browser_pg.list.on().lvn_item_changed(move |p| {
                if p.uNewState.has(co::LVIS::SELECTED) && p.iItem >= 0 {
                    let mut st = app.state.lock().unwrap();
                    st.browser_grid.selected_row = Some(p.iItem as usize);
                    let txt = st.browser_grid.format_inspector_crlf();
                    let _ = app.browser_pg.inspector.set_text(&txt);
                }
                Ok(())
            });
        }

        // Menu Bar Commands
        let wire_menu = |id: u16, handler: Box<dyn Fn(&Win32App)>| {
            let app = self.clone();
            self.wnd.on().wm_command_acc_menu(id, move || {
                handler(&app);
                Ok(())
            });
        };
        wire_menu(IDM_OPEN_FOLDER, Box::new(|a| a.trigger_browse_and_load()));
        wire_menu(IDM_LOAD_DEFAULT_BROWSER, Box::new(|a| a.load_selected_browser()));
        wire_menu(IDM_EXTRACT_CACHE, Box::new(|a| a.trigger_extract_cache()));
        wire_menu(
            IDM_EXPORT_CSV,
            Box::new(|a| a.trigger_export_cache(ExportFormat::Csv, "chrome_cache_export.csv", "csv", ("CSV", "*.csv"))),
        );
        wire_menu(
            IDM_EXPORT_TSV,
            Box::new(|a| a.trigger_export_cache(ExportFormat::Tab, "chrome_cache_export.tsv", "tsv", ("TSV", "*.tsv"))),
        );
        wire_menu(
            IDM_EXPORT_TABULAR,
            Box::new(|a| {
                a.trigger_export_cache(
                    ExportFormat::Tabular,
                    "chrome_cache_tabular.txt",
                    "txt",
                    ("Tabular Text", "*.txt"),
                )
            }),
        );
        wire_menu(
            IDM_EXPORT_TEXT,
            Box::new(|a| {
                a.trigger_export_cache(
                    ExportFormat::Text,
                    "chrome_cache_records.txt",
                    "txt",
                    ("Plain Text", "*.txt"),
                )
            }),
        );
        wire_menu(
            IDM_EXPORT_HTML_H,
            Box::new(|a| {
                a.trigger_export_cache(
                    ExportFormat::HtmlHorizontal,
                    "chrome_cache_table.html",
                    "html",
                    ("HTML Table", "*.html"),
                )
            }),
        );
        wire_menu(
            IDM_EXPORT_HTML_V,
            Box::new(|a| {
                a.trigger_export_cache(
                    ExportFormat::HtmlVertical,
                    "chrome_cache_cards.html",
                    "html",
                    ("HTML Cards", "*.html"),
                )
            }),
        );
        wire_menu(
            IDM_EXPORT_XML,
            Box::new(|a| a.trigger_export_cache(ExportFormat::Xml, "chrome_cache_export.xml", "xml", ("XML", "*.xml"))),
        );
        wire_menu(
            IDM_EXPORT_JSON,
            Box::new(|a| {
                a.trigger_export_cache(
                    ExportFormat::Json,
                    "chrome_cache_export.json",
                    "json",
                    ("JSON", "*.json"),
                )
            }),
        );
        wire_menu(IDM_EXPORT_URLS, Box::new(|a| a.trigger_export_urls()));
        wire_menu(IDM_REPORT_HTML, Box::new(|a| a.trigger_report(ReportFormat::Html)));
        wire_menu(IDM_REPORT_JSON, Box::new(|a| a.trigger_report(ReportFormat::Json)));
        wire_menu(IDM_REPORT_MD, Box::new(|a| a.trigger_report(ReportFormat::Markdown)));
        wire_menu(IDM_REPORT_ALL, Box::new(|a| a.trigger_report(ReportFormat::All)));
        wire_menu(
            IDM_EXIT,
            Box::new(|a| {
                let _ = a.wnd.hwnd().DestroyWindow();
            }),
        );
        wire_menu(
            IDM_COPY_URLS,
            Box::new(|a| {
                let sel = a.selected_cache_row_indices();
                let mut st = a.state.lock().unwrap();
                let urls: Vec<String> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .map(|e| e.url.clone())
                    .collect();
                if !urls.is_empty() && copy_to_clipboard(&urls.join("\n")) {
                    st.status_message = format!("Copied {} URL(s) to clipboard.", urls.len());
                    a.refresh_status_bar(&st);
                }
            }),
        );
        wire_menu(
            IDM_COPY_TSV,
            Box::new(|a| {
                let sel = a.selected_cache_row_indices();
                let mut st = a.state.lock().unwrap();
                let entries: Vec<_> = st
                    .selected_or_filtered_entries(&sel, !sel.is_empty())
                    .into_iter()
                    .cloned()
                    .collect();
                if let Ok(tsv) = chrome2rust_cache::export::render_cache_export(
                    &entries,
                    ExportFormat::Tab,
                    &st.active_cache_columns,
                    true,
                    st.show_millis,
                ) && copy_to_clipboard(&tsv)
                {
                    st.status_message = format!("Copied {} cache row(s) as TSV.", entries.len());
                    a.refresh_status_bar(&st);
                }
            }),
        );
        wire_menu(
            IDM_COPY_PREVIEW,
            Box::new(|a| {
                if let Ok(txt) = a.cache_pg.inspector.text()
                    && copy_to_clipboard(&txt)
                {
                    let mut st = a.state.lock().unwrap();
                    st.status_message = "Copied inspector text to clipboard.".to_string();
                    a.refresh_status_bar(&st);
                }
            }),
        );
        wire_menu(
            IDM_ENTRY_PROPS,
            Box::new(|a| {
                let msg = {
                    let st = a.state.lock().unwrap();
                    st.selected_cache_entry().map(|e| st.format_entry_properties(e))
                };
                if let Some(txt) = msg {
                    let _ = a
                        .wnd
                        .hwnd()
                        .MessageBox(&txt, "Cache Entry Properties", co::MB::ICONINFORMATION);
                }
            }),
        );
        wire_menu(IDM_DELETE_CACHE, Box::new(|a| a.trigger_delete_selected()));
        wire_menu(
            IDM_TOGGLE_ZERO,
            Box::new(|a| {
                {
                    let mut st = a.state.lock().unwrap();
                    st.hide_zero_length = !st.hide_zero_length;
                    a.cache_pg.chk_no_zero.set_check(st.hide_zero_length);
                    st.apply_cache_filter();
                }
                a.refresh_cache_list_and_preview();
            }),
        );
        wire_menu(
            IDM_TOGGLE_MILLIS,
            Box::new(|a| {
                a.state.lock().unwrap().show_millis ^= true;
                a.refresh_cache_list_and_preview();
                a.refresh_timeline_tab();
            }),
        );
        wire_menu(
            IDM_TOGGLE_DETECTED_EXT,
            Box::new(|a| {
                let mut st = a.state.lock().unwrap();
                st.extract_prefer_detected_ext = !st.extract_prefer_detected_ext;
                let state_str = if st.extract_prefer_detected_ext { "ON" } else { "OFF" };
                st.status_message = format!("Extraction prefer detected extension: {state_str}");
                a.refresh_status_bar(&st);
            }),
        );
        wire_menu(
            IDM_TOGGLE_WEBSITE_DIRS,
            Box::new(|a| {
                let mut st = a.state.lock().unwrap();
                st.extract_website_dirs = !st.extract_website_dirs;
                let state_str = if st.extract_website_dirs { "ON" } else { "OFF" };
                st.status_message = format!("Extraction website directory structure: {state_str}");
                a.refresh_status_bar(&st);
            }),
        );
        wire_menu(
            IDM_TOGGLE_PEANUTS,
            Box::new(|a| {
                let mut st = a.state.lock().unwrap();
                st.allow_peanuts = !st.allow_peanuts;
                let state_str = if st.allow_peanuts { "ON" } else { "OFF" };
                st.status_message =
                    format!("Linux Chromium 'peanuts' key fallback: {state_str} (reload target to apply)");
                a.refresh_status_bar(&st);
            }),
        );
        wire_menu(
            IDM_PREVIEW_AUTO,
            Box::new(|a| {
                a.state.lock().unwrap().preview_mode = PreviewMode::Auto;
                a.refresh_cache_list_and_preview();
            }),
        );
        wire_menu(
            IDM_PREVIEW_HEADERS,
            Box::new(|a| {
                a.state.lock().unwrap().preview_mode = PreviewMode::Headers;
                a.refresh_cache_list_and_preview();
            }),
        );
        wire_menu(
            IDM_PREVIEW_HEX,
            Box::new(|a| {
                a.state.lock().unwrap().preview_mode = PreviewMode::Hex;
                a.refresh_cache_list_and_preview();
            }),
        );
        wire_menu(IDM_CUSTODY_AUDIT, Box::new(|a| a.trigger_custody_audit()));
        for idx in 0u16..9u16 {
            wire_menu(
                IDM_TAB_BASE + idx,
                Box::new(move |a| {
                    a.select_tab_index(u32::from(idx));
                    if idx == 8 {
                        a.refresh_browser_tools_tab();
                    }
                }),
            );
        }
        wire_menu(
            IDM_ABOUT,
            Box::new(|a| {
                let _ = a.wnd.hwnd().MessageBox(
                    concat!(
                        "Chrome2Rust Forensic Workstation v",
                        env!("CARGO_PKG_VERSION"),
                        "\nNative Win32 Edition (WinSafe, zero GPU dependencies)\nPart of the GUAP Ecosystem (guap.ca)\nLicensed under Apache-2.0",
                    ),
                    "About Chrome2Rust",
                    co::MB::ICONINFORMATION,
                );
            }),
        );
    }
}
