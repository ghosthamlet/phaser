use clap::{ArgMatches};
use crate::scanner::{
    modules,
    BaseModule,
};


// TODO
pub fn run(_: &ArgMatches) -> Result<(), String> {

    println!("{}", modules::Ports{}.name());

    modules::get_host_modules().iter().for_each(|module| {
        println!("{}", module.name());
    });

    modules::get_port_modules().iter().for_each(|module| {
        println!("{}", module.name());
    });

    Ok(())
}
