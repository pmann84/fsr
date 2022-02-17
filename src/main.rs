use std::fs::{DirEntry, Metadata};
use std::{env, fs, io};
use std::path::PathBuf;
use std::path::Path;
use ansi_term::Style;
use ansi_term::Colour::{White, Black, Red, Blue};
use filetime::FileTime;
use chrono::prelude::DateTime;
use chrono::{NaiveDateTime, Utc};
// TODO: Add colours for file types
// TODO: Permissions

// namespace fs
// {
// void output_path_permissions(const std::filesystem::path& path, bool is_directory)
// {
// auto p = std::filesystem::status(path).permissions();
// std::string dir_marker = is_directory ? "d" : "-";
// if (is_directory)
// {
// std::cout << tc::fg::blue;
// }
// std::cout << " " << dir_marker << tc::reset;
// std::cout << ((p & std::filesystem::perms::owner_read) != std::filesystem::perms::none ? "r" : "-")
// << ((p & std::filesystem::perms::owner_write) != std::filesystem::perms::none ? "w" : "-")
// << ((p & std::filesystem::perms::owner_exec) != std::filesystem::perms::none ? "x" : "-")
// << ((p & std::filesystem::perms::group_read) != std::filesystem::perms::none ? "r" : "-")
// << ((p & std::filesystem::perms::group_write) != std::filesystem::perms::none ? "w" : "-")
// << ((p & std::filesystem::perms::group_exec) != std::filesystem::perms::none ? "x" : "-")
// << ((p & std::filesystem::perms::others_read) != std::filesystem::perms::none ? "r" : "-")
// << ((p & std::filesystem::perms::others_write) != std::filesystem::perms::none ? "w" : "-")
// << ((p & std::filesystem::perms::others_exec) != std::filesystem::perms::none ? "x" : "-");
// }
//
// bool is_file_extension_in_list(const std::filesystem::directory_entry& entry, const std::vector<std::string>& valid_extensions)
// {
// return std::find(valid_extensions.begin(), valid_extensions.end(), entry.path().extension()) != valid_extensions.end();
// }
//
// bool is_binary_file(const std::filesystem::directory_entry& entry)
// {
// std::vector<std::string> binary_extensions = { ".exe", ".so", ".dll", ".class", ".obj", ".pyc" };
// return is_file_extension_in_list(entry, binary_extensions);
// }
//
// bool is_source_file(const std::filesystem::directory_entry& entry)
// {
// std::vector<std::string> source_extensions = {
// ".cpp", ".c", ".hpp", ".h",
// ".cs",
// ".py",
// ".js", ".java", ".rb", ".pl", ".php",
// ".sh", ".ps1", ".psm1" };
// return is_file_extension_in_list(entry, source_extensions);
// }
//
// bool is_image_file(const std::filesystem::directory_entry& entry)
// {
// std::vector<std::string> image_extensions = {
// ".jpg", ".jpeg", ".png", ".gif",
// ".bmp", ".tiff", ".psd", ".mp4",
// ".mkv", ".avi", ".mov", ".mpg",
// ".vob", ".heic" };
// return is_file_extension_in_list(entry, image_extensions);
// }
//
// //    Audio: mp3, aac, wav, flac, ogg, mka, wma, ...
// //    Documents: pdf, doc, xls, ppt, docx, odt, ...
// //    Archive: zip, rar, 7z, tar, iso, ...
// //    Database: mdb, accde, frm, sqlite, ...
// //    Web standards: html, xml, css, svg, json, ...
// //    Documents: txt, tex, markdown, asciidoc, rtf, ps, ...
// //    Configuration: ini, cfg, rc, reg, ...
// //    Tabular data: csv, tsv, ...


fn parse_config(args: &[String]) -> Vec<String> {
    //println!("{:?}", args);
    let mut input_dirs = args.clone().to_vec();
    &input_dirs.remove(0);
    if input_dirs.len() == 0 {
        input_dirs.push(String::from("."));
    }
    input_dirs.to_vec()
}

fn get_last_write_time_string(file_metadata: &Metadata) -> String {
    let lwt = FileTime::from_last_modification_time(&file_metadata).unix_seconds();
    let naive = NaiveDateTime::from_timestamp(lwt, 0);
    let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    datetime.format("%Y-%m-%d %H:%M").to_string()
}

fn get_permissions_string(is_dir: bool) -> &'static str {
    if is_dir {
        "d---------"
    } else {
        "----------"
    }
}

fn get_extension_from_filename(filename: &str) -> &str {
    match Path::new(filename).extension() {
        None => {
            filename
        }
        Some(extension) => {
            extension.to_str().unwrap()
        }
    }
}

fn get_absolute_path(relative_path: &str) -> String {
    let abs_path = fs::canonicalize(PathBuf::from(&relative_path)).unwrap().to_str().unwrap().to_string();
    let parent_path = abs_path.split_at(4).1.to_string(); // Hack because the canonicalized path has //?/ at the front
    parent_path
}

enum ListEntryType {
    Directory,
    File
}

impl Default for ListEntryType {
    fn default() -> Self { ListEntryType::Directory }
}

fn get_list_entry_type(is_dir: bool) -> ListEntryType {
    if is_dir {
        ListEntryType::Directory
    } else {
        ListEntryType::File
    }
}

enum ListFileType {
    None,
    // Archive,
    // Audio,
    // Binary,
    // Document,
    // Image,
    // Source,
    // Web
}

impl Default for ListFileType {
    fn default() -> Self { ListFileType::None }
}

fn get_list_file_type(filename: &str) -> ListFileType {
    match get_extension_from_filename(filename) {
        _ => ListFileType::None
    }
}

#[derive(Default)]
struct ListEntry {
    name: String,
    size: u64,
    last_write: String,
    permissions: String,
    entry_type: ListEntryType,
    _file_type: ListFileType
}

fn get_list_entry_from_file_metadata(filename: &str, file_metadata: &Metadata) -> ListEntry {
    let is_dir = file_metadata.is_dir();
    let child = ListEntry {
        name: filename.to_string(),
        size: file_metadata.len(),
        last_write: get_last_write_time_string(&file_metadata),
        permissions: get_permissions_string(is_dir).to_string(),
        entry_type: get_list_entry_type(is_dir),
        _file_type: get_list_file_type(filename)
    };
    child
}

fn get_list_entry_from_dir_entry(file_entry: &DirEntry) -> ListEntry {
    let filepath = file_entry.path();
    let filename = filepath.file_name().unwrap().to_str().unwrap();
    let file_metadata = file_entry.metadata().unwrap();
    get_list_entry_from_file_metadata(&filename, &file_metadata)
}

#[derive(Default)]
struct DirectoryListing {
    root_path: String,
    children: Vec<ListEntry>,
    exists: bool
}

impl std::fmt::Display for DirectoryListing {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let root_copy = self.root_path.clone();
        write!(f, "{}\n", Black.on(White).paint(root_copy));
        if self.exists {
            // Calculate column sizes before printing
            let size_col_size = self.children.iter().fold(0, |len, item| {
                let item_size = item.size.to_string().chars().count();
                if item_size > len {
                    item_size
                } else {
                    len
                }
            });

            let size_header = format!("{: >width$}", "Size", width = size_col_size);
            let last_write_header = format!("{: >16}", "Last Write");
            // Write the headings
            write!(f, "{: >11} {: >} {: >} {:<}\n",
                   Style::new().underline().paint("Permissions"),
                   Style::new().underline().paint(last_write_header),
                   Style::new().underline().paint(size_header),
                   Style::new().underline().paint("Name")
            );
            for child in &self.children {
                match child.entry_type {
                    ListEntryType::Directory => {
                        write!(f, "{: >11} {: >16} {: >width$} {:<}\n", child.permissions, child.last_write, child.size, Blue.paint(&child.name), width = size_col_size);
                    }
                    ListEntryType::File => {
                        write!(f, "{: >11} {: >16} {: >width$} {:<}\n", child.permissions, child.last_write, child.size, child.name, width = size_col_size);
                    }
                }
            }
        } else {
            write!(f, "{}", White.on(Red).paint("Directory does not exist."));
        }
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let dirs_to_query = parse_config(&args);

    // Check for help
    if dirs_to_query.contains(&String::from("-h")) || dirs_to_query.contains(&String::from("--help")) {
        println!("Usage: fsr [-h|--help] [path [PATH ...]]\n\nPositional Arguments:\npath: Path(s) to list.\n\nOptional Arguments:\n-h, --help: Show this help message and exit.");
        std::process::exit(0);
    }

    let mut listings: Vec<DirectoryListing> = Vec::new();

    // First pass - read files
    for dir in dirs_to_query {
        match fs::read_dir(&dir) {
            Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
                let new_listing = DirectoryListing {
                    root_path: dir,
                    children: Vec::new(),
                    exists: false
                };
                listings.push(new_listing);
                continue
            },
            // Handle if the input is a file not a directory
            Err(ref error) if error.raw_os_error().unwrap() == 267 => {
                let dirpath = dir.clone();
                let rootpath = get_absolute_path(&dir);
                let metadata = fs::metadata(dirpath).unwrap();
                let mut listing : DirectoryListing = DirectoryListing::default();
                listing.root_path = rootpath.to_string();
                listing.exists = true;
                listing.children.push(get_list_entry_from_file_metadata(&dir,&metadata));
                listings.push(listing);
                continue
            },
            Err(error) => {
                println!("Error {:?} ({:?}): {:?}", error.kind(), error.raw_os_error(), error.to_string())
            },
            Ok(paths) => {
                let mut listing : DirectoryListing = DirectoryListing::default();
                listing.exists = true;
                listing.root_path = get_absolute_path(&dir);

                // Add all the children
                let all_paths: Vec<io::Result<DirEntry>> = paths.collect();
                for path in all_paths {
                    let child = get_list_entry_from_dir_entry(&path.unwrap());
                    listing.children.push(child);
                }

                listings.push(listing);
            }
        }
    }

    // Second Pass - Output
    for listing in listings {
        println!("{}", listing)
    }
}
