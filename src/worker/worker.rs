use config::Config;
use std::str::FromStr;
use std::path::{Path};
use reqwest::header;
use std::{thread, time};
use std::io::{Write, Seek, Read};
use zip::{
    write::FileOptions,
    result::ZipError,
};
use walkdir::{WalkDir, DirEntry};
use std::fs::File;
use crate::{
    worker::{config, models},
    scanner,
    log::macros::*,
};



#[derive(Clone)]
pub struct Worker {
    id: u64,
    config: config::Config,
    api_client: reqwest::Client,
    logger: slog::Logger,
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
     pub fn new(id: u64) -> Worker {
        let config = Config::new();

        let mut headers = header::HeaderMap::new();
        let auth_header = format!("Secret phaser:{}", &config.phaser_secret);
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth_header).unwrap());

        let logger = slog_scope::logger().new(slog_o!("worker" => id));

        let api_client = reqwest::Client::builder()
            .gzip(true)
            .timeout(time::Duration::from_secs(30))
            .default_headers(headers)
            .build().expect("error building api client");
        return Worker{
            id,
            config,
            api_client,
            logger,
        };
     }

    pub fn run(&self) {
        let endpoint = format!("{}/phaser/v1/job", self.config.api_url);

        loop {
            slog_info!(self.logger, "fetching job {}", &endpoint);
            let mut res = continue_fail!(self.api_client.get(&endpoint).send());
            slog_info!(self.logger, "status: {}", res.status());
            if res.status() == 200 {
                let payload: models::ApiResponse = continue_fail!(res.json());
                let payload = payload.data.expect("error unwraping reportJob");
                slog_info!(self.logger, "job received report: {}", &payload.id);
                let targets = payload.targets
                    .iter().map(|target| scanner::Target::from_str(target).unwrap()).collect();
                let data_folder = Path::new(&self.config.data_folder)
                    .join(&payload.id.to_string()).to_str().expect("error creating data folder path").to_string();
                let config = scanner::ConfigV1{
                    data_folder,
                    assets_folder: self.config.assets_folder.clone(),
                };
                let mut report = scanner::ReportV1::new(config, payload.id, payload.scan_id, targets);
                report.run();

                let zip_file = format!("{}.zip", &report.config.data_folder);
                continue_fail!(
                    doit(&report.config.data_folder, &zip_file, zip::CompressionMethod::Deflated)
                );

                let form = continue_fail!(
                    reqwest::multipart::Form::new()
                    .file("report.zip", &zip_file)
                );

                // TODO: retry
                let endpoint = format!("{}/phaser/v1/scans/{}/reports/{}/complete", &self.config.api_url, report.scan_id, report.id);
                match self.api_client.post(&endpoint)
                    .multipart(form)
                    .send() {
                    Ok(_) => slog_info!(self.logger, "report zip successfully sent to API"),
                    Err(err) => slog_warn!(self.logger, "error sending report to api"; "err" => err.to_string()),
                }
            } else {
                slog_info!(self.logger, "no jobs, waiting 15 secs");
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
            info!("adding file {:?} as {:?} ...", path, name);
            zip.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
            buffer.clear();
        } else if name.as_os_str().len() != 0 {
            // Only if not root! Avoids path spec / warning
            // and mapname conversion failed error on unzip
            info!("adding dir {:?} as {:?} ...", path, name);
            zip.add_directory_from_path(name, options)?;
        }
    }
    zip.finish()?;
    Result::Ok(())
}
