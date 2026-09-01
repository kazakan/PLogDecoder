use plog_gui::App;

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "PLog Decoder",
        eframe::NativeOptions::default(),
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
