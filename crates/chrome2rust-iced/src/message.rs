use chrome2rust_cache::CacheSortField;
use chrome2rust_cache::export::{CacheColumn, ExportFormat, ExtractFilenameMode};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_report::ReportFormat;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTab {
    CacheInspector,
    Overview,
    Findings,
    Timeline,
    HistoryDownloads,
    CredsCookies,
    ExtensionsBookmarks,
    SessionsStorage,
    BrowserTools,
}

impl WorkspaceTab {
    pub const fn all() -> &'static [Self] {
        &[
            Self::CacheInspector,
            Self::Overview,
            Self::Findings,
            Self::Timeline,
            Self::HistoryDownloads,
            Self::CredsCookies,
            Self::ExtensionsBookmarks,
            Self::SessionsStorage,
            Self::BrowserTools,
        ]
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::CacheInspector => "Cache Inspector",
            Self::Overview => "Overview & Reports",
            Self::Findings => "Forensic Findings",
            Self::Timeline => "Unified Timeline",
            Self::HistoryDownloads => "History & Downloads",
            Self::CredsCookies => "Cookies, Logins & Autofill",
            Self::ExtensionsBookmarks => "Extensions & Bookmarks",
            Self::SessionsStorage => "Sessions & Storage",
            Self::BrowserTools => "Multi-Browser & Carvers",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    ExtractCache,
    ExportCacheTable,
    DecryptionSettings,
    ChooseColumns,
    EntryProperties,
    ConfirmDelete,
    CustodyManifest,
    About,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewMode {
    Auto,
    Headers,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentQuickCat {
    All,
    Images,
    Html,
    ScriptsStyles,
    JsonXml,
    MediaFonts,
}

impl ContentQuickCat {
    pub const ALL: &'static [Self] = &[
        Self::All,
        Self::Images,
        Self::Html,
        Self::ScriptsStyles,
        Self::JsonXml,
        Self::MediaFonts,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Images => "Images",
            Self::Html => "HTML",
            Self::ScriptsStyles => "JS/CSS",
            Self::JsonXml => "JSON/XML",
            Self::MediaFonts => "Media/Fonts",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySubTab {
    Urls,
    Visits,
    Downloads,
    SearchTerms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredSubTab {
    Logins,
    Cookies,
    Autofill,
    AddressesCards,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSubTab {
    Tabs,
    LocalStorage,
    SessionStorage,
    MiscInventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportFormatChoice(pub ExportFormat);

impl ExportFormatChoice {
    pub const ALL: &'static [Self] = &[
        Self(ExportFormat::Csv),
        Self(ExportFormat::Tab),
        Self(ExportFormat::Tabular),
        Self(ExportFormat::Text),
        Self(ExportFormat::HtmlHorizontal),
        Self(ExportFormat::HtmlVertical),
        Self(ExportFormat::Xml),
        Self(ExportFormat::Json),
    ];
}

impl fmt::Display for ExportFormatChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbl = match self.0 {
            ExportFormat::Csv => "Comma-Delimited (CSV)",
            ExportFormat::Tab => "Tab-Delimited (TSV)",
            ExportFormat::Tabular => "Tabular Text",
            ExportFormat::Text => "Plain Text Records",
            ExportFormat::HtmlHorizontal => "HTML Table Report (Horizontal)",
            ExportFormat::HtmlVertical => "HTML Record Cards (Vertical)",
            ExportFormat::Xml => "XML Structured Feed",
            ExportFormat::Json => "JSON Array",
        };
        f.write_str(lbl)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilenameModeChoice(pub ExtractFilenameMode);

impl FilenameModeChoice {
    pub const ALL: &'static [Self] = &[
        Self(ExtractFilenameMode::BasedOnUrl),
        Self(ExtractFilenameMode::CacheName),
        Self(ExtractFilenameMode::CacheNameWithExtension),
    ];
}

impl fmt::Display for FilenameModeChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbl = match self.0 {
            ExtractFilenameMode::BasedOnUrl => "Based on URL",
            ExtractFilenameMode::CacheName => "Cache Name",
            ExtractFilenameMode::CacheNameWithExtension => "Cache Name + Ext",
        };
        f.write_str(lbl)
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    // Target loading & worker
    PathInputChanged(String),
    BrowseAndLoad,
    LoadFromInput,
    LoadPath(PathBuf),
    PollWorker,
    ToggleDarkMode,

    // Sidebar / Navigation
    SelectProfile(Option<usize>),
    SelectTab(WorkspaceTab),
    ToggleConsoleTree,
    TogglePreviewPane,

    // Cache Inspector filters, sorting & selection
    QuickFilterChanged(String),
    ClearQuickFilter,
    SetContentCat(ContentQuickCat),
    ToggleHideZeroLength(bool),
    ToggleShowMillis(bool),
    ToggleSort(CacheSortField, bool),
    SelectCacheRow(usize),
    ToggleRowInSelection(usize),
    SelectAllFiltered,
    InvertSelectionFiltered,
    ClearSelection,

    // Inspector & Clipboard
    SetPreviewMode(PreviewMode),
    CopySelectedUrls,
    CopySelectedRowsTsv,
    CopyPreviewToClipboard,
    InspectEntryProperties(usize),

    // Forensic workspace tabs
    SetFindingSeverityFilter(Option<FindingSeverity>),
    SetTimelineCategoryFilter(String),
    ForensicSearchChanged(String),
    SetHistorySubTab(HistorySubTab),
    SetCredSubTab(CredSubTab),
    SetSessionSubTab(SessionSubTab),
    SelectTabNav(usize, usize),

    // Reports & Modals
    SaveReport(ReportFormat),
    OpenModal(ActiveModal),
    CloseModal,

    // Extract cache modal
    ExtractOnlySelectedToggled(bool),
    ExtractOutputDirChanged(String),
    BrowseExtractOutputDir,
    ExtractFilenameModeChanged(FilenameModeChoice),
    ExtractWebsiteDirsToggled(bool),
    ExtractUpdateMtimeToggled(bool),
    ExtractNewNameToggled(bool),
    ExtractDecompressToggled(bool),
    ExtractPreferDetectedExtToggled(bool),
    ConfirmExtractCache,

    // Export cache table modal
    ExportOnlySelectedToggled(bool),
    ExportFormatChanged(ExportFormatChoice),
    ExportIncludeHeaderToggled(bool),
    ConfirmExportCacheTable,

    // Decryption modal
    CryptoDecryptToggled(bool),
    CryptoPeanutsToggled(bool),
    CryptoKeysChanged(String),
    ApplyCryptoAndReload,

    // Columns modal
    ToggleCacheColumn(CacheColumn, bool),
    ResetDefaultColumns,

    // Delete confirmation
    ConfirmDeleteSelected,

    // Custody manifest
    ComputeCustodyManifest,
    SaveCustodyManifest,

    // Multi-Browser & Carvers guap-gui-iced DataGrid
    BrowserToolsGrid(guap_gui_iced::DataGridMessage),
}
