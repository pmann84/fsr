use std::fs::{DirEntry, Metadata};
use std::{env, fs, io};
use std::path::PathBuf;
use std::path::Path;
use ansi_term::Style;
use ansi_term::Colour::{White, Black, Red};
use filetime::FileTime;
use chrono::prelude::DateTime;
use chrono::{NaiveDateTime, Utc};
use std::collections::HashMap;
use std::ffi::OsStr;


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
    Archive,
    Audio,
    Binary,
    Document,
    Image,
    Source,
    Web
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
    file_type: ListFileType
}

fn get_list_entry_from_file_metadata(filename: &str, file_metadata: &Metadata) -> ListEntry {
    let is_dir = file_metadata.is_dir();
    let child = ListEntry {
        name: filename.to_string(),
        size: file_metadata.len(),
        last_write: get_last_write_time_string(&file_metadata),
        permissions: get_permissions_string(is_dir).to_string(),
        entry_type: get_list_entry_type(is_dir),
        file_type: get_list_file_type(filename)
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

fn main() {
    let args: Vec<String> = env::args().collect();
    let dirs_to_query = parse_config(&args);
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


    println!("Hello!");
}

// let mut print_path = dir.to_string();
// print_path.push_str(":");
// println!("{}", Black.on(White).paint(print_path));
// println!("{}", White.on(Red).paint("Directory does not exist."));
// println!();

// let file_entry = path.unwrap();
// let file_metadata = file_entry.metadata().unwrap();
// let permissions_str = format!(" {}---------", if file_metadata.is_dir() {"d"} else {"-"});
// let lwt = FileTime::from_last_modification_time(&file_metadata).unix_seconds();
// let naive = NaiveDateTime::from_timestamp(lwt, 0);
// let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
// let timestamp_str = datetime.format("%Y-%m-%d %H:%M").to_string();

// println!(
//     "{0: >10} {1: <10} {2: <10}  {3: <10}",
//     permissions_str, timestamp_str, file_metadata.len(), file_entry.path().file_name().unwrap().to_str().unwrap()
// )

// // println!("{}", Black.on(White).paint(parent_path));
//
// // Now collect together all the paths under this root
// let children: Vec<file_list_entry> = Vec::new();
//
// let all_paths: Vec<io::Result<DirEntry>> = paths.collect();
// let total_files = all_paths.len();
// let num_dirs = all_paths.iter().filter(|&p| p.as_ref().unwrap().path().is_dir()).count();
// let num_files = total_files - num_dirs;
// println!("Total: {} ({} files, {} dirs)", total_files, num_files, num_dirs);
// println!(
//     "{0: >10} {1: <16} {2: <10}  {3: <10}",
//     Style::new().underline().paint("Permissions"),
//     Style::new().underline().paint("      Last Write"),
//     Style::new().underline().paint("Size"),
//     Style::new().underline().paint("Name")
// );
//
// let mut dir_listings : Vec<file_list_entry> = Vec::new();
//
// for path in all_paths {
//     let file_entry = path.unwrap();
//     let file_metadata = file_entry.metadata().unwrap();
//     let permissions_str = format!(" {}---------", if file_metadata.is_dir() {"d"} else {"-"});
//     let lwt = FileTime::from_last_modification_time(&file_metadata).unix_seconds();
//     let naive = NaiveDateTime::from_timestamp(lwt, 0);
//     let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
//     let timestamp_str = datetime.format("%Y-%m-%d %H:%M").to_string();
//     println!(
//         "{0: >10} {1: <10} {2: <10}  {3: <10}",
//         permissions_str, timestamp_str, file_metadata.len(), file_entry.path().file_name().unwrap().to_str().unwrap()
//     )
// }
// println!();