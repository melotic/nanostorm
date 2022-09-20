// pwntools style logging

macro_rules! log {
    ($style:expr, $($arg:tt)*) => {
        println!("[{}] {}", $style, format_args!($($arg)*));
    };
}

macro_rules! status {
    ($($arg:tt)*) => {
        log!("x".magenta(), $($arg)*);
    };
}

macro_rules! success {
    ($($arg:tt)*) => {
        log!("+".bold().green(), $($arg)*);
    };
}

macro_rules! failure {
    ($($arg:tt)*) => {
        log!("-".bold().red(), $($arg)*);
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        log!("DEBUG".bold().red(), $($arg)*);
    };
}

macro_rules! warning {
    ($($arg:tt)*) => {
        log!("!".bold().yellow(), $($arg)*);
    };
}

macro_rules! error {
    ($($arg:tt)*) => {
        log!("ERROR".on_red(), $($arg)*);
    };
}

macro_rules! exception {
    ($($arg:tt)*) => {
        log!("ERROR".on_red(), $($arg)*);
    };
}

macro_rules! critical {
    ($($arg:tt)*) => {
        log!("CRITICAL".on_red(), $($arg)*);
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        log!("*".bright_blue().bold(), $($arg)*);
    };
}