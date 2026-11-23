pub mod cache_list;
pub mod forensic_tabs;
pub mod inspector_pane;
pub mod modals;
pub mod sidebar;

use crate::message::Message;
use iced::widget::{column, container, row, rule, text};
use iced::{Alignment, Element, Length};

pub fn section_card<'a>(title: impl Into<String>, content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    let title_str: String = title.into();
    let body = column![text(title_str).size(14), rule::horizontal(1), content.into()].spacing(8);

    container(body)
        .width(Length::Fill)
        .padding(10)
        .style(container::bordered_box)
        .into()
}

pub fn page_header<'a>(title: &'a str, right_controls: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    row![text(title).size(16).width(Length::Fill), right_controls.into()]
        .align_y(Alignment::Center)
        .spacing(8)
        .into()
}
