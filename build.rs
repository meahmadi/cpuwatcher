fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/tray.ico"); // use your icon here
    res.compile().unwrap();
}
