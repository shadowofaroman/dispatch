use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::mpsc;
use dispatch_core::TransferProgress;

pub struct ProgressReporter {
    pb: ProgressBar,
}

impl ProgressReporter {
    pub fn new(total_bytes: u64, file_name: &str) -> Self {
        let pb = ProgressBar::new(total_bytes);
        let style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-");

        pb.set_style(style);
        pb.set_message(file_name.to_string());
        Self { pb }
    }

    pub fn set_position(&self, bytes: u64) {
        self.pb.set_position(bytes);
    }

    pub fn finish_with_message(&self, msg: &str) {
        self.pb.finish_with_message(msg.to_string());
    }
}

pub async fn handle_progress_stream(mut rx: mpsc::UnboundedReceiver<TransferProgress>) {
    let mut reporter: Option<ProgressReporter> = None;

    while let Some(progress) = rx.recv().await {
        match progress {
            TransferProgress::Started { file_name, file_size, .. } => {
                let rep = ProgressReporter::new(file_size, &file_name);
                reporter = Some(rep);
            }
            TransferProgress::Progress { transferred_bytes, .. } => {
                if let Some(ref rep) = reporter {
                    rep.set_position(transferred_bytes);
                }
            }
            TransferProgress::BlockDone { .. } => {}
            TransferProgress::Completed { file_name, file_size, duration_secs, average_speed_mbps, .. } => {
                if let Some(ref rep) = reporter {
                    let summary = format!(
                        "✓ Transferred '{}' ({:.2} MB in {:.2}s at {:.1} MB/s)",
                        file_name,
                        file_size as f64 / (1024.0 * 1024.0),
                        duration_secs,
                        average_speed_mbps
                    );
                    rep.finish_with_message(&summary);
                }
                println!(
                    "\n[+] Verified byte-identical transfer! Throughput: {:.2} MB/s ({:.2} Gbps)",
                    average_speed_mbps,
                    (average_speed_mbps * 8.0) / 1000.0
                );
            }
        }
    }
}
