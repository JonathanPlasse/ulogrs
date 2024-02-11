use ulogrs::parse_ulog;

fn main() {
    let input = std::fs::read("/home/jonathan/Downloads/1st_3_logs/10_47_33.ulg").unwrap();
    let ulog = parse_ulog(&input).unwrap();
    println!("{:?}", ulog);
}
