use std::process::Command;

pub struct SuiCli;

impl SuiCli {
    pub fn command(&self) -> Command {
        let mut cmd = Command::new("sui");
        cmd
    }

    pub fn get_active_wallet(&self) -> Result<String, std::io::Error> {
        let mut cmd = self.command();
        cmd.arg("client")
        .arg("active-address")
        .arg("--json");
        
        let output = cmd.output().expect(" the program crashed");

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, 
                format!(
                    "Command failed:\nStatus: {}\nStderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
            )) 
        }
    }
}

