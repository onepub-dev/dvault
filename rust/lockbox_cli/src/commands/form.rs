use std::{
    fs,
    io::{Read, Write},
};

use lockbox_core::{
    Error, FormFieldDefinition, FormFieldKind, FormValue, LockboxPath, SecretString,
};

use super::context::{cli_error, open_existing, open_or_create, require_arg, Access, CliResult};
use super::output::{output_format_from_args, print_records};
use crate::secret_prompt::prompt_secret;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let subcommand = require_arg(args, 0, "form command")?;
    match subcommand {
        "define" => define(&args[1..], access),
        "definitions" | "types" => definitions(&args[1..], access),
        "add" => add(&args[1..], access),
        "edit" => edit(&args[1..], access),
        "set" => set(&args[1..], access),
        "get" => get(&args[1..], access),
        "show" => inspect(&args[1..], access),
        "list" => list(&args[1..], access),
        "rm" => remove(&args[1..], access),
        _ => Err(Error::InvalidInput(format!("unknown form command: {subcommand}")).into()),
    }
}

fn define(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let mut alias = None;
    let mut name = None;
    let mut type_id = None;
    let mut fields = Vec::new();
    let mut index = 1;
    if let Some(value) = args.get(index).filter(|value| !value.starts_with("--")) {
        alias = Some(value.clone());
        name = Some(value.clone());
        index += 1;
    }
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                index += 1;
                name = Some(require_arg(args, index, "--name value")?.to_string());
            }
            "--definition-id" | "--type-id" => {
                index += 1;
                type_id = Some(lockbox_core::FormTypeId::new(require_arg(
                    args,
                    index,
                    "--definition-id value",
                )?)?);
            }
            "--field" => {
                index += 1;
                fields.push(parse_field_spec(require_arg(
                    args,
                    index,
                    "--field value",
                )?)?);
            }
            value => {
                return Err(Error::InvalidInput(format!(
                    "unexpected form define argument: {value}"
                ))
                .into());
            }
        }
        index += 1;
    }
    let name = name.ok_or_else(|| {
        Error::InvalidInput("form define requires an alias or --name".to_string())
    })?;
    let alias = alias.unwrap_or_else(|| name.clone());
    let mut lb = open_or_create(lockbox_path, access)?;
    let definition = if let Some(type_id) = type_id {
        lb.define_form_with_type_id(type_id, &alias, &name, fields)?
    } else {
        lb.define_form(&alias, &name, fields)?
    };
    lb.commit()?;
    println!("Form definition saved.");
    println!("  alias: {}", definition.alias);
    println!("  definition_id: {}", definition.type_id);
    println!("  revision: {}", definition.revision);
    println!("  name: {}", definition.name);
    println!("  fields: {}", definition.fields.len());
    Ok(())
}

fn definitions(args: &[String], access: &Access) -> CliResult<()> {
    let (args, format) = output_format_from_args(args)?;
    let lockbox_path = require_arg(&args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    let rows = lb
        .list_form_definitions()?
        .into_iter()
        .map(|definition| {
            vec![
                definition.alias,
                definition.type_id.to_string(),
                definition.revision.to_string(),
                definition.name,
                definition.fields.len().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    print_records(
        &["alias", "definition_id", "revision", "name", "fields"],
        rows,
        format,
    )?;
    Ok(())
}

fn add(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = form_record_path(require_arg(args, 1, "form path")?)?;
    let mut form_type = None;
    let mut name = None;
    let mut assignments = Vec::new();
    let mut interactive = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--type" => {
                index += 1;
                form_type = Some(require_arg(args, index, "--type value")?.to_string());
            }
            "--name" => {
                index += 1;
                name = Some(require_arg(args, index, "--name value")?.to_string());
            }
            "--set" => {
                index += 1;
                assignments.push(parse_field_assignment(require_arg(
                    args,
                    index,
                    "--set FIELD=VALUE",
                )?)?);
            }
            "--interactive" => interactive = true,
            value => {
                return Err(
                    Error::InvalidInput(format!("unexpected form add argument: {value}")).into(),
                );
            }
        }
        index += 1;
    }
    let form_type =
        form_type.ok_or_else(|| Error::InvalidInput("form add requires --type".to_string()))?;
    let name = name.unwrap_or_else(|| default_form_name(path.as_str()));
    let mut lb = open_or_create(lockbox_path, access)?;
    let record = lb.create_form_record(&path, &form_type, &name)?;
    let definition = lb.resolve_form_definition(record.type_id.as_str())?;
    for (field_id, value) in assignments {
        let field = definition
            .fields
            .iter()
            .find(|field| field.id == field_id)
            .ok_or_else(|| Error::InvalidInput(format!("unknown form field: {field_id}")))?;
        if field.kind.is_secret() {
            return Err(Error::InvalidInput(format!(
                "field {field_id} is secret; use --interactive or form set --secret --stdin"
            ))
            .into());
        }
        lb.set_form_field_normal(&path, &field_id, &value)?;
    }
    if interactive {
        fill_missing_fields_interactively(&mut lb, &path, &definition)?;
    }
    lb.commit()?;
    println!("{}\t{}\t{}", record.path, record.name, record.type_id);
    Ok(())
}

fn edit(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = form_record_path(require_arg(args, 1, "form path")?)?;
    let mut assignments = Vec::new();
    let mut interactive = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--set" => {
                index += 1;
                assignments.push(parse_field_assignment(require_arg(
                    args,
                    index,
                    "--set FIELD=VALUE",
                )?)?);
            }
            "--interactive" => interactive = true,
            value => {
                return Err(
                    Error::InvalidInput(format!("unexpected form edit argument: {value}")).into(),
                );
            }
        }
        index += 1;
    }
    if assignments.is_empty() && !interactive {
        return Err(
            Error::InvalidInput("form edit requires --set or --interactive".to_string()).into(),
        );
    }
    let mut lb = open_existing(lockbox_path, access)?;
    let record = lb
        .get_form_record(&path)?
        .ok_or_else(|| Error::NotFound(format!("form record {path}")))?;
    let definition = lb.resolve_form_definition(record.type_id.as_str())?;
    for (field_id, value) in assignments {
        let field = definition
            .fields
            .iter()
            .find(|field| field.id == field_id)
            .ok_or_else(|| Error::InvalidInput(format!("unknown form field: {field_id}")))?;
        if field.kind.is_secret() {
            return Err(Error::InvalidInput(format!(
                "field {field_id} is secret; use --interactive or form set --secret --stdin"
            ))
            .into());
        }
        lb.set_form_field_normal(&path, &field_id, &value)?;
    }
    if interactive {
        edit_fields_interactively(&mut lb, &path, &definition)?;
    }
    lb.commit()?;
    Ok(())
}

fn set(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = form_record_path(require_arg(args, 1, "form path")?)?;
    let field_id = require_arg(args, 2, "field id")?;
    let mut source = None;
    let mut secret = false;
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "-i" | "--interactive" => set_source(&mut source, FieldValueSource::Interactive)?,
            "-t" | "--stdin" => set_source(&mut source, FieldValueSource::Stdin)?,
            "-v" | "--value" => {
                index += 1;
                set_source(
                    &mut source,
                    FieldValueSource::Value(require_arg(args, index, "--value value")?.to_string()),
                )?;
            }
            "-f" | "--file" => {
                index += 1;
                set_source(
                    &mut source,
                    FieldValueSource::File(require_arg(args, index, "--file value")?.to_string()),
                )?;
            }
            "-e" | "--from-env" => {
                index += 1;
                set_source(
                    &mut source,
                    FieldValueSource::FromEnv(
                        require_arg(args, index, "--from-env value")?.to_string(),
                    ),
                )?;
            }
            "--secret" => secret = true,
            value if source.is_none() => {
                set_source(&mut source, FieldValueSource::Literal(value.to_string()))?
            }
            value => {
                return Err(
                    Error::InvalidInput(format!("unexpected form set argument: {value}")).into(),
                );
            }
        }
        index += 1;
    }
    let source =
        source.ok_or_else(|| Error::InvalidInput("missing form field value".to_string()))?;
    let mut lb = open_existing(lockbox_path, access)?;
    if secret {
        let value = read_secret_value(source)?;
        lb.set_form_field_secret(&path, field_id, &value)?;
    } else {
        let value = read_normal_value(source)?;
        lb.set_form_field_normal(&path, field_id, &value)?;
    }
    lb.commit()?;
    println!("{}\t{}\tupdated", path, field_id);
    Ok(())
}

fn remove(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = form_record_path(require_arg(args, 1, "form path")?)?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.delete_form_record(&path)?;
    lb.commit()?;
    Ok(())
}

fn get(args: &[String], access: &Access) -> CliResult<()> {
    let request = FormGetRequest::parse(args)?;
    let path = form_record_path(&request.path)?;
    let lb = open_existing(&request.lockbox_path, access)?;
    let value = lb
        .get_form_field(&path, &request.field_id)?
        .ok_or_else(|| Error::NotFound(format!("form field {}", request.field_id)))?;
    match value.value {
        FormValue::Normal(value) => request.write_value(value.as_bytes())?,
        FormValue::Secret(value) if request.reveal_secret => {
            value.with_str(|value| request.write_value(value.as_bytes()))??;
        }
        FormValue::Secret(_) => {
            return Err(cli_error("field is secret; pass --secret to print it"));
        }
    }
    Ok(())
}

struct FormGetRequest {
    lockbox_path: String,
    path: String,
    field_id: String,
    reveal_secret: bool,
    output: Option<String>,
    overwrite: bool,
}

impl FormGetRequest {
    fn parse(args: &[String]) -> CliResult<Self> {
        let lockbox_path = require_arg(args, 0, "lockbox")?.to_string();
        let path = require_arg(args, 1, "form path")?.to_string();
        let field_id = require_arg(args, 2, "field id")?.to_string();
        let mut reveal_secret = false;
        let mut output = None;
        let mut overwrite = false;
        let mut index = 3;
        while index < args.len() {
            match args[index].as_str() {
                "--secret" => reveal_secret = true,
                "--output" => {
                    index += 1;
                    output = Some(require_arg(args, index, "--output value")?.to_string());
                }
                "--overwrite" => overwrite = true,
                value => {
                    return Err(Error::InvalidInput(format!(
                        "unexpected form get argument: {value}"
                    ))
                    .into());
                }
            }
            index += 1;
        }
        if overwrite && output.is_none() {
            return Err(Error::InvalidInput("--overwrite requires --output".to_string()).into());
        }
        Ok(Self {
            lockbox_path,
            path,
            field_id,
            reveal_secret,
            output,
            overwrite,
        })
    }

    fn write_value(&self, bytes: &[u8]) -> CliResult<()> {
        if let Some(path) = &self.output {
            write_output_file(path, bytes, self.overwrite)?;
        } else {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            stdout.write_all(bytes)?;
            stdout.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn write_output_file(path: &str, bytes: &[u8], overwrite: bool) -> CliResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    configure_private_output_file(&mut options);
    let mut file = options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Error::AlreadyExists(path.to_string())
        } else {
            Error::Io(format!("create {path}: {err}"))
        }
    })?;
    set_private_output_permissions(&file)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn configure_private_output_file(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_private_output_file(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_private_output_permissions(file: &fs::File) -> CliResult<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_output_permissions(_file: &fs::File) -> CliResult<()> {
    Ok(())
}

fn inspect(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = form_record_path(require_arg(args, 1, "form path")?)?;
    let lb = open_existing(lockbox_path, access)?;
    let record = lb
        .get_form_record(&path)?
        .ok_or_else(|| Error::NotFound(format!("form record {path}")))?;
    let definition = lb.resolve_form_definition(record.type_id.as_str())?;
    println!("path\t{}", record.path);
    println!("name\t{}", record.name);
    println!("alias\t{}", record.definition_alias);
    println!("definition_id\t{}", record.type_id);
    println!("revision\t{}", record.definition_revision);
    for field in &definition.fields {
        let value = record
            .values
            .iter()
            .find(|value| value.field_id == field.id);
        let display = match value.map(|value| &value.value) {
            Some(FormValue::Normal(value)) => value.clone(),
            Some(FormValue::Secret(_)) => "<secret>".to_string(),
            None => String::new(),
        };
        println!("field\t{}\t{}\t{}", field.id, field.label, display);
    }
    for value in &record.values {
        if definition
            .fields
            .iter()
            .all(|field| field.id != value.field_id)
        {
            println!(
                "unknown-field\t{}\t{}",
                value.field_id, value.captured_label
            );
        }
    }
    Ok(())
}

fn list(args: &[String], access: &Access) -> CliResult<()> {
    let (args, format) = output_format_from_args(args)?;
    let lockbox_path = require_arg(&args, 0, "lockbox")?;
    let pattern = args.get(1).map(String::as_str);
    let lb = open_existing(lockbox_path, access)?;
    let rows = lb
        .list_form_records()?
        .into_iter()
        .filter(|record| {
            pattern.is_none_or(|pattern| form_path_matches(pattern, record.path.as_str()))
        })
        .map(|record| {
            vec![
                record.path.to_string(),
                record.name,
                record.definition_alias,
                record.type_id.to_string(),
                record.definition_revision.to_string(),
            ]
        })
        .collect::<Vec<_>>();
    print_records(
        &["path", "name", "alias", "definition_id", "revision"],
        rows,
        format,
    )?;
    Ok(())
}

enum FieldValueSource {
    Interactive,
    Literal(String),
    Value(String),
    File(String),
    Stdin,
    FromEnv(String),
}

fn parse_field_spec(spec: &str) -> CliResult<FormFieldDefinition> {
    let mut parts = spec.splitn(4, ':');
    let id = parts.next().unwrap_or_default().to_string();
    let kind = match parts.next() {
        Some(kind) => parse_field_kind(kind)?,
        None => FormFieldKind::Text,
    };
    let required = matches!(parts.next(), Some("required"));
    let label = parts
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or(&id)
        .to_string();
    Ok(FormFieldDefinition {
        id,
        label,
        kind,
        required,
    })
}

fn parse_field_assignment(spec: &str) -> CliResult<(String, String)> {
    let Some((field, value)) = spec.split_once('=') else {
        return Err(
            Error::InvalidInput("form field assignment must be FIELD=VALUE".to_string()).into(),
        );
    };
    if field.is_empty() {
        return Err(Error::InvalidInput("form field id cannot be empty".to_string()).into());
    }
    Ok((field.to_string(), value.to_string()))
}

fn default_form_name(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("form")
        .to_string()
}

fn fill_missing_fields_interactively(
    lb: &mut lockbox_core::Lockbox,
    path: &LockboxPath,
    definition: &lockbox_core::FormDefinition,
) -> CliResult<()> {
    let record = lb
        .get_form_record(path)?
        .ok_or_else(|| Error::NotFound(format!("form record {path}")))?;
    for field in &definition.fields {
        if record.values.iter().any(|value| value.field_id == field.id) {
            continue;
        }
        if field.kind.is_secret() {
            let value = prompt_secret(&format!("{}: ", field.label))?;
            if !field.required && value.is_empty() {
                continue;
            }
            lb.set_form_field_secret(path, &field.id, &value)?;
        } else {
            let value = prompt_normal_field(&field.label)?;
            if !field.required && value.is_empty() {
                continue;
            }
            lb.set_form_field_normal(path, &field.id, &value)?;
        }
    }
    Ok(())
}

fn edit_fields_interactively(
    lb: &mut lockbox_core::Lockbox,
    path: &LockboxPath,
    definition: &lockbox_core::FormDefinition,
) -> CliResult<()> {
    let record = lb
        .get_form_record(path)?
        .ok_or_else(|| Error::NotFound(format!("form record {path}")))?;
    for field in &definition.fields {
        let existing = record
            .values
            .iter()
            .find(|value| value.field_id == field.id)
            .map(|value| &value.value);
        if field.kind.is_secret() {
            let value = prompt_secret(&format!("{}: ", field.label))?;
            if value.is_empty() && (existing.is_some() || !field.required) {
                continue;
            }
            lb.set_form_field_secret(path, &field.id, &value)?;
        } else {
            let existing_normal = match existing {
                Some(FormValue::Normal(value)) => Some(value.as_str()),
                _ => None,
            };
            let value = prompt_normal_field_with_default(&field.label, existing_normal)?;
            if value.is_empty() && (existing.is_some() || !field.required) {
                continue;
            }
            lb.set_form_field_normal(path, &field.id, &value)?;
        }
    }
    Ok(())
}

fn prompt_normal_field(label: &str) -> CliResult<String> {
    prompt_normal_field_with_default(label, None)
}

fn prompt_normal_field_with_default(label: &str, default: Option<&str>) -> CliResult<String> {
    if let Some(default) = default {
        print!("{label} [{default}]: ");
    } else {
        print!("{label}: ");
    }
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(trim_trailing_newline(value))
}

fn parse_field_kind(value: &str) -> CliResult<FormFieldKind> {
    match value {
        "text" => Ok(FormFieldKind::Text),
        "secret" | "password" => Ok(FormFieldKind::Secret),
        "url" => Ok(FormFieldKind::Url),
        "email" => Ok(FormFieldKind::Email),
        "date" => Ok(FormFieldKind::Date),
        "month" => Ok(FormFieldKind::Month),
        "notes" => Ok(FormFieldKind::Notes),
        "number" => Ok(FormFieldKind::Number),
        "otp" => Ok(FormFieldKind::Otp),
        _ => Err(Error::InvalidInput(format!("unsupported form field kind: {value}")).into()),
    }
}

fn set_source(target: &mut Option<FieldValueSource>, source: FieldValueSource) -> CliResult<()> {
    if target.is_some() {
        return Err(
            Error::InvalidInput("form set accepts exactly one value source".to_string()).into(),
        );
    }
    *target = Some(source);
    Ok(())
}

fn read_normal_value(source: FieldValueSource) -> CliResult<String> {
    Ok(match source {
        FieldValueSource::Interactive => prompt_normal_field("Value")?,
        FieldValueSource::Literal(value) => value,
        FieldValueSource::Value(value) => value,
        FieldValueSource::File(path) => trim_trailing_newline(String::from_utf8(fs::read(path)?)?),
        FieldValueSource::Stdin => {
            let mut value = String::new();
            std::io::stdin().lock().read_to_string(&mut value)?;
            trim_trailing_newline(value)
        }
        FieldValueSource::FromEnv(name) => std::env::var(name)?,
    })
}

fn read_secret_value(source: FieldValueSource) -> CliResult<SecretString> {
    match &source {
        FieldValueSource::Literal(_) | FieldValueSource::Value(_) => {
            return Err(Error::InvalidInput(
                "secret form fields require --stdin, --file, --interactive, or --from-env"
                    .to_string(),
            )
            .into());
        }
        FieldValueSource::Interactive => return Ok(prompt_secret("Secret value: ")?),
        FieldValueSource::FromEnv(name) => {
            return SecretString::try_from_env(name)?
                .ok_or_else(|| Error::InvalidInput(format!("{name} is not set")).into());
        }
        FieldValueSource::File(_) | FieldValueSource::Stdin => {}
    }
    let value = read_normal_value(source)?;
    Ok(SecretString::try_from_bytes(value.into_bytes())?)
}

fn trim_trailing_newline(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn form_record_path(value: &str) -> CliResult<LockboxPath> {
    let value = if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    };
    Ok(LockboxPath::new(value)?)
}

fn form_path_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        let pattern = pattern.trim_start_matches('/');
        let path = path.trim_start_matches('/');
        return glob_matches(pattern, path);
    }
    let pattern = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/{pattern}")
    };
    path == pattern
        || path
            .strip_prefix(&pattern)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut dp = vec![false; text.len() + 1];
    dp[0] = true;
    for &p in pattern {
        let mut next = vec![false; text.len() + 1];
        match p {
            b'*' => {
                next[0] = dp[0];
                for index in 0..text.len() {
                    next[index + 1] = dp[index + 1] || next[index] || dp[index];
                }
            }
            b'?' => {
                for index in 0..text.len() {
                    next[index + 1] = dp[index];
                }
            }
            byte => {
                for index in 0..text.len() {
                    next[index + 1] = dp[index] && text[index] == byte;
                }
            }
        }
        dp = next;
    }
    dp[text.len()]
}
