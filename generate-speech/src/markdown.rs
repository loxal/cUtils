use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use regex::Regex;

pub fn to_plain_text(md: &str) -> String {
    let md = md.trim();
    if md.is_empty() {
        return String::new();
    }
    let parser = Parser::new(md);
    let mut parts = Vec::new();
    let mut in_code_block = false;

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(_)) => in_code_block = true,
            Event::End(TagEnd::CodeBlock) => in_code_block = false,
            _ if in_code_block => continue,
            Event::Text(t) => parts.push(t.to_string()),
            Event::Code(t) => parts.push(t.to_string()),
            Event::SoftBreak | Event::HardBreak => parts.push("\n".to_string()),
            _ => {}
        }
    }

    let text = parts.join("");
    Regex::new(r"\n{3,}")
        .unwrap()
        .replace_all(&text, "\n\n")
        .trim()
        .to_string()
}
