use lockbox_core::Error;

use super::context::CliResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputFormat {
    Table,
    Tsv,
    Json,
}

impl OutputFormat {
    pub(crate) fn parse(value: Option<&str>) -> CliResult<Self> {
        match value.unwrap_or("table") {
            "table" => Ok(Self::Table),
            "tsv" => Ok(Self::Tsv),
            "json" => Ok(Self::Json),
            value => Err(Error::InvalidInput(format!(
                "unsupported output format: {value}; expected table, tsv, or json"
            ))
            .into()),
        }
    }
}

pub(crate) fn output_format_from_args(args: &[String]) -> CliResult<(Vec<String>, OutputFormat)> {
    let mut out = Vec::new();
    let mut format = OutputFormat::Table;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--format" {
            index += 1;
            let Some(value) = args.get(index).map(String::as_str) else {
                return Err(Error::InvalidInput("missing --format value".to_string()).into());
            };
            format = OutputFormat::parse(Some(value))?;
        } else {
            out.push(args[index].clone());
        }
        index += 1;
    }
    Ok((out, format))
}

pub(crate) fn print_records(
    headers: &[&str],
    rows: Vec<Vec<String>>,
    format: OutputFormat,
) -> CliResult<()> {
    if rows.is_empty() {
        println!("empty");
        return Ok(());
    }
    match format {
        OutputFormat::Table => print_table(headers, &rows),
        OutputFormat::Tsv => print_tsv(&rows),
        OutputFormat::Json => print_json(headers, &rows)?,
    }
    Ok(())
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths = headers
        .iter()
        .map(|header| header.len())
        .collect::<Vec<_>>();
    for row in rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(value.len());
            }
        }
    }
    print_table_row(
        &headers
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        &widths,
    );
    for row in rows {
        print_table_row(row, &widths);
    }
}

fn print_table_row(row: &[String], widths: &[usize]) {
    for (index, value) in row.iter().enumerate() {
        if index > 0 {
            print!("  ");
        }
        let width = widths.get(index).copied().unwrap_or(value.len());
        print!("{value:<width$}");
    }
    println!();
}

fn print_tsv(rows: &[Vec<String>]) {
    for row in rows {
        println!("{}", row.join("\t"));
    }
}

fn print_json(headers: &[&str], rows: &[Vec<String>]) -> CliResult<()> {
    for row in rows {
        if row.len() != headers.len() {
            return Err(Error::InvalidInput("output row/header width mismatch".to_string()).into());
        }
        let fields = headers
            .iter()
            .zip(row.iter())
            .map(|(name, value)| format!("\"{}\":\"{}\"", json_escape(name), json_escape(value)))
            .collect::<Vec<_>>();
        println!("{{{}}}", fields.join(","));
    }
    Ok(())
}

pub(crate) fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}
