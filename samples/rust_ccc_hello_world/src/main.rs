extern crate rust_ccc;

use std::io;
use std::io::{Write, BufReader, BufRead};
use crate::rust_ccc::rustccc::ContainerFile;

fn main() -> io::Result<()> {
    let rcc = ContainerFile::create(
        "../sample_container.vc",
        &"password",
        512 * 512
    )?;

    let unlocked = rcc.is_unlocked();
    if unlocked {
        let fs = rcc.mount()?;

        let root_dir = fs.root_dir();

        for f in root_dir.iter() {
            let e = f?;
            println!("file name: {:?}", e.file_name());
        }

        println!("---");
        println!("writing file...");

        let mut file = root_dir.create_file("helloWorld.txt")?;
        file.write_all(b"Hello World")?;
        file.flush()?;

        println!("---");
        println!("Content of 'helloWorld.txt':");

        let file = root_dir.open_file("helloWorld.txt")?;
        let buffered = BufReader::new(file);

        for line in buffered.lines() {
            println!("{}", line?);
        }
    }
    Ok(())
}
