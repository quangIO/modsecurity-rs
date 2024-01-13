# Rust binding for libmodsecurity

This crate provides a high-level Rust wrapper around the C++ implementation of libmodsecurity.

## Requirements

Using the library required having libmodsecurity installed.

- Debian/Ubuntu: `sudo apt install libmodsecurity`
- Fedora/Centos: `sudo dnf install libmodsecurity`
- Arch Linux: `sudo pacman -S libmodsecurity`

## Example

``` rust
fn main() -> anyhow::Result<()> {
    let mut modsec = ModSecurity::new();
    let mut rules = RulesSet::from_paths(&["resource/sample-ruleset.conf"])?;
    let mut tx = Transaction::new(&mut modsec, &mut rules);
    tx.process_connection("127.0.0.1".parse().unwrap(), 31337, "localhost", 80)?;
    tx.process_uri("/test.pl?param1=test&para2=test2", "GET", "1.1")?;
    tx.add_request_header("Host", "foo.bar")?;
    tx.process_request_headers()?;
    tx.process_request_body()?;
    let it = tx.intervention()?;
    assert_eq!(it.status, 403);
    assert!(!it.pause);
    assert!(it.disruptive);
    assert!(it.log.len() > 0);
    assert!(it.url.is_empty());
    tx.process_logging()?;
    Ok(())
}
```
