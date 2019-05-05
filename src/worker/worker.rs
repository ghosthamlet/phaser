use config::Config;
use crate::log::macros::*;
use std::str::FromStr;
use crate::worker::{config, messages};
use crate::scanner;
use std::path::{Path};
use reqwest::header;
use std::{thread, time};
use std::fs;
use std::io::Read;

use std::io::prelude::*;
use std::io::{Write, Seek};
use std::iter::Iterator;
use zip::write::FileOptions;
use zip::result::ZipError;

use walkdir::{WalkDir, DirEntry};
use std::fs::File;


#[derive(Clone)]
pub struct Worker {
    config: config::Config,
    api_client: reqwest::Client,
}

macro_rules! continue_fail {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                warn!("An error: {}; continue.", e);
                continue;
            }
        }
    };
}

impl Worker {
     pub fn new() -> Worker {
        let config = Config::new();

        let mut headers = header::HeaderMap::new();
        let auth_header = format!("Secret {}", &config.phaser_secret);
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth_header).unwrap());

        let api_client = reqwest::Client::builder()
            .gzip(true)
            .timeout(time::Duration::from_secs(30))
            .default_headers(headers)
            .build().expect("error building api client");
        return Worker{
            config,
            api_client,
        };
     }

    pub fn run(&self) {
        let endpoint = format!("{}/phaser/job", self.config.api_url);

        loop {
            info!("fetching job {}", &endpoint);
            let mut res = continue_fail!(self.api_client.get(&endpoint).send());
            let res: messages::ApiResponse = continue_fail!(res.json());
            if res.status == 200 {
                match res.data {
                    Some(messages::ApiData::ScanQueued(ref payload)) => {
                        info!("job received report: {}", &payload.report_id);
                        let targets = payload.targets
                            .iter().map(|target| scanner::Target::from_str(target).unwrap()).collect();
                        let data_folder = Path::new(&self.config.data_folder)
                            .join(&payload.report_id).to_str().expect("error creating data folder path").to_string();
                        let config = scanner::Config{
                            data_folder,
                            assets_folder: self.config.assets_folder.clone(),
                        };
                        let mut scan = scanner::Scan::new(config, &payload.scan_id, &payload.report_id, targets);
                        scan.run();

                        let mut f = fs::File::open(&format!("{}/{}/scan.json", &self.config.data_folder, &payload.report_id)).unwrap();
                        let mut contents: Vec<u8> = Vec::new();
                        match f.read_to_end(&mut contents) {
                            Err(why) => panic!("Error opening file to send to S3: {}", why),
                            Ok(_) => {
                                // TODO: zip

                                let folder = format!("{}/{}", &self.config.data_folder, &payload.report_id);
                                let zip_file = format!("{}.zip", &folder);
                                continue_fail!(
                                    doit(&folder, &zip_file, zip::CompressionMethod::Deflated)
                                );

                                // TODO: retry
                                continue_fail!(self.api_client.put(&endpoint)
                                    // .json(&messages::ScanCompleted{report_id: payload.report_id.clone()})
                                    .send());
                            }
                        }
                    },
                    _ => {},
                }
            } else {
                info!("no jobs, waiting 15 secs");
                thread::sleep(time::Duration::from_secs(15))
            }
        }
    }
}


fn doit(src_dir: &str, dst_file: &str, method: zip::CompressionMethod) -> zip::result::ZipResult<()> {
    if !Path::new(src_dir).is_dir() {
        return Err(ZipError::FileNotFound);
    }

    let path = Path::new(dst_file);
    let file = File::create(&path).unwrap();

    let walkdir = WalkDir::new(src_dir.to_string());
    let it = walkdir.into_iter();

    zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method)?;

    Ok(())
}


fn zip_dir<T>(it: &mut Iterator<Item=DirEntry>, prefix: &str, writer: T, method: zip::CompressionMethod)
              -> zip::result::ZipResult<()>
    where T: Write+Seek
{
    let mut zip = zip::ZipWriter::new(writer);
    let options = FileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(prefix)).unwrap();

        // Write file or directory explicitly
        // Some unzip tools unzip files with directory paths correctly, some do not!
        if path.is_file() {
            println!("adding file {:?} as {:?} ...", path, name);
            zip.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
            buffer.clear();
        } else if name.as_os_str().len() != 0 {
            // Only if not root! Avoids path spec / warning
            // and mapname conversion failed error on unzip
            println!("adding dir {:?} as {:?} ...", path, name);
            zip.add_directory_from_path(name, options)?;
        }
    }
    zip.finish()?;
    Result::Ok(())
}
