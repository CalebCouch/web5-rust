use super::structs::DateTime;

pub struct Logger {}
impl Logger {
    pub fn info(msg: &str) {
        println!("INFO[{}]: {}", DateTime::now(), msg);
    }

    pub fn debug(msg: &str) {
        println!("DEBUG[{}]: {}", DateTime::now(), msg);
    }

    pub fn error(msg: &str) {
        println!("ERROR[{}]: {}", DateTime::now(), msg);
    }
}
