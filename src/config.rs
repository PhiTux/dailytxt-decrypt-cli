pub struct Config {
    pub help: bool,
    pub user: String,
    pub password: String,
    pub all: bool,
    pub to_single_file: bool,
    pub month: u32,
    pub year: u32,
    pub from_path: String,
    pub to_path: String,
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
            return Ok(Config {
                help: true,
                user: String::from(""),
                password: String::from(""),
                all: false,
                to_single_file: false,
                month: 0,
                year: 0,
                from_path: String::from(""),
                to_path: String::from(""),
            });
        } else if args.len() < 7 {
            return Err("Not enough arguments given");
        }

        let mut help = false;
        let mut user = String::from("");
        let mut password = String::from("");
        let mut all = true;
        let mut to_single_file = false;
        let mut month = 0;
        let mut year = 0;

        let mut i = 1;
        while i < args.len() - 2 {
            let arg = args[i].as_str();
            match arg {
                "-u" | "--user" => {
                    i += 1;
                    user = match args.get(i) {
                        Some(x) => x.clone(),
                        None => return Err("No user given"),
                    }
                }
                "-p" | "--password" => {
                    i += 1;
                    password = match args.get(i) {
                        Some(x) => x.clone(),
                        None => return Err("No password given"),
                    }
                }
                "-a" | "--all" => all = true,
                "-s" | "--single" => all = false,
                "--to-single-file" => to_single_file = true,
                "-m" | "--month" => {
                    month = match args.get(args.iter().position(|x| x == arg).unwrap() + 1) {
                        Some(x) => match x.parse() {
                            Ok(num) => num,
                            Err(_) => return Err("Month is not a number"),
                        },
                        None => return Err("No month given"),
                    };
                    i += 1;
                }
                "-y" | "--year" => {
                    year = match args.get(args.iter().position(|x| x == arg).unwrap() + 1) {
                        Some(x) => match x.parse() {
                            Ok(num) => num,
                            Err(_) => return Err("Year is not a number"),
                        },
                        None => return Err("No year given"),
                    };
                    i += 1;
                }
                "-h" | "--help" => help = true,
                other => {
                    println!("Unknown argument: {}", other);
                    return Err("Unknown argument");
                }
            }
            i += 1;
        }

        let from_path = args[args.len() - 2].clone();
        let to_path = args[args.len() - 1].clone();

        // check for logic mismatch
        if !all && (month == 0 || year == 0) {
            return Err("No month or year given");
        } else if all && (month != 0 || year != 0) {
            return Err("Month or year given but not needed, since -a or --all is set");
        } else if user == "" || password == "" {
            return Err("No user or password given");
        }

        Ok(Config {
            help,
            user,
            password,
            all,
            to_single_file,
            month,
            year,
            from_path,
            to_path,
        })
    }
}
