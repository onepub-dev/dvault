use super::context::{open_existing, require_arg, Access, CliResult};
use lockbox_core::{ListOptions, Lockbox, LockboxPath};

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    print_lockbox_visualization(&lb)
}

fn print_lockbox_visualization(lb: &Lockbox) -> CliResult<()> {
    println!("Lockbox");
    println!("  id: {}", lb.lockbox_id());
    let inspector = lb.inspector();
    println!("  size: {} bytes", inspector.storage_len()?);

    let key_slot_count = lb.list_key_slots().len();
    let env_count = lb.list_env()?.len();
    let mut file_count = 0usize;
    let mut symlink_count = 0usize;
    let mut total_file_bytes = 0u64;
    for entry in lb.list(ListOptions {
        path: LockboxPath::new("/")?,
        glob: None,
        recursive: true,
        include_files: true,
        include_symlinks: true,
        limit: None,
    })? {
        let entry = entry?;
        match entry.kind {
            lockbox_core::LockboxEntryKind::File => {
                file_count += 1;
                total_file_bytes = total_file_bytes.saturating_add(entry.len);
            }
            lockbox_core::LockboxEntryKind::Symlink => symlink_count += 1,
        }
    }

    println!("  summary:");
    println!("    files: {file_count}");
    println!("    symlinks: {symlink_count}");
    println!("    env vars: {env_count}");
    println!("    key slots: {key_slot_count}");
    println!("    logical file bytes: {total_file_bytes}");

    println!("  pages:");
    let pages = inspector.inspect_pages()?;
    if pages.is_empty() {
        println!("    <none>");
    } else {
        for page in pages {
            println!("    ----------------------------------------");
            println!("    offset: {}", page.offset);
            println!("    page id: {}", page.page_id);
            println!("    sequence: {}", page.sequence);
            println!("    encrypted body: {} bytes", page.encrypted_body_len);
            println!("    objects: {}", page.object_count);
            for object in page.objects {
                println!(
                    "      {:<18} id={:<8} payload={} bytes",
                    object.kind, object.id, object.payload_len
                );
            }
        }
    }

    let report = inspector.recovery_report();
    println!("  recovery scan:");
    println!("    intact files: {}", report.intact_file_count);
    println!("    partial files: {}", report.partial_files);
    println!("    corrupt records/pages: {}", report.corrupt_records);
    println!("    TOC recovered: {}", report.toc_recovered);

    Ok(())
}
