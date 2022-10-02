// pwntools style logging

macro_rules! log {
    ($style:expr, $($arg:tt)*) => {
        println!("[{}] {}", $style, format_args!($($arg)*))
    }
}

macro_rules! success {
    ($($arg:tt)*) => {
        log!("+".bold().green(), $($arg)*)
    }
}

macro_rules! warning {
    ($($arg:tt)*) => {
        log!("!".bold().yellow(), $($arg)*)
    }
}

macro_rules! info {
    ($($arg:tt)*) => {
        log!("*".bright_blue().bold(), $($arg)*)
    }
}
