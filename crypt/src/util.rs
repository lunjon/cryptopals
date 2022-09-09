use super::{Error, Result};
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

pub fn read_bytes(filename: &str) -> Result<Vec<u8>> {
    let mut reader = open(filename)?;
    let mut buf = Vec::new();

    match reader.read_to_end(&mut buf) {
        Ok(_) => Ok(buf),
        Err(err) => Err(Error::DataError(format!(
            "failed to read file bytes: {}",
            err
        ))),
    }
}

pub fn read_lines(filename: &str) -> Result<Vec<String>> {
    let reader = open(filename)?;
    let lines = reader
        .lines()
        .filter_map(|line| match line {
            Ok(s) => Some(s.trim().to_owned()),
            Err(_) => None,
        })
        .collect();
    Ok(lines)
}

pub fn read_string(filename: &str) -> Result<String> {
    let mut reader = open(filename)?;

    let mut buf = String::new();
    match reader.read_to_string(&mut buf) {
        Ok(_) => Ok(buf),
        Err(err) => Err(Error::DataError(format!(
            "failed to read file as string: {}",
            err
        ))),
    }
}

pub fn read_stdin() -> Result<Vec<u8>> {
    let stdin = io::stdin();
    let mut buf = Vec::new();

    let r = stdin.lock().read_to_end(&mut buf);
    match r {
        Ok(_) => Ok(buf),
        Err(err) => Err(Error::ArgError(format!(
            "error reading bytes from stdin: {}",
            err
        ))),
    }
}

pub fn write_bytes(filename: &str, b: &[u8]) -> Result<()> {
    let mut opt = match OpenOptions::new().create(true).write(true).open(filename) {
        Ok(f) => BufWriter::new(f),
        Err(err) => return Err(Error::ArgError(format!("error opening file: {}", err))),
    };

    match opt.write_all(b) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::DataError(format!("failed to write file: {}", err))),
    }
}

pub fn write_stdout(b: &[u8]) -> Result<()> {
    match io::stdout().write_all(b) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::DataError(format!("failed to write stdout: {}", err))),
    }
}

pub fn slices_equal<T>(a: &[T], b: &[T]) -> bool
where
    T: PartialEq,
{
    if a.len() != b.len() {
        return false;
    }

    for index in 0..a.len() {
        let x = &a[index];
        let y = &b[index];
        if !x.eq(&y) {
            return false;
        }
    }
    return true;
}

/// Calculates the length of the prefixes of `a` and `b`
/// given that they have the same tail:
///     a = [ p1  ][ tail ]
///     b = [   p2   ][ tail ]
/// If the tail is the same it returns Some((|p1|, |p2|)),
/// else None.
pub fn slices_prefix_len<T>(block_size: usize, a: &[T], b: &[T]) -> Option<(usize, usize)>
where
    T: PartialEq + Debug,
{
    if a.is_empty() || b.is_empty() {
        return None;
    }

    // Sweeping window
    let a_end = a.len() - block_size + 1;
    let b_end = b.len() - block_size + 1;

    for a_start in 0..a_end {
        let x = &a[a_start..a_start + block_size];
        for b_start in 0..b_end {
            let y = &b[b_start..b_start + block_size];
            if slices_equal(x, y) {
                return Some((a_start, b_start));
            }
        }
    }
    None
}

// Takes a multiline string and joines all into a single line.
pub fn into_line(s: &str) -> String {
    let lines: Vec<String> = s
        .trim()
        .lines()
        .map(|line| line.trim().to_string())
        .collect();
    lines.join("")
}

fn open(filename: &str) -> Result<BufReader<File>> {
    match File::open(filename) {
        Ok(f) => Ok(BufReader::new(f)),
        Err(err) => Err(Error::ArgError(format!("error opening file: {}", err))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bytes() {
        let b = read_bytes("Cargo.toml").unwrap();
        assert!(b.len() > 0);
    }

    #[test]
    fn test_read_lines() {
        let lines = read_lines("Cargo.toml").unwrap();
        assert!(lines.len() > 0);
    }

    #[test]
    fn test_read_string() {
        let s = read_string("Cargo.toml").unwrap();
        assert!(s.len() > 0);
    }

    #[test]
    fn test_read_unknown() {
        assert!(read_lines("doEs_Not-exist.txt").is_err());
    }

    #[test]
    fn test_slices_equal() {
        let a = &["a", "b", "c"];
        let b = &["a", "b", "c"];
        assert!(slices_equal(a, b));

        let a = &["a", "b", "c"];
        let b = &["a", "c", "b"];
        assert!(!slices_equal(a, b));

        let a = &["a", "b", "c"];
        let b = &["a", "b"];
        assert!(!slices_equal(a, b));
    }

    #[test]
    fn test_slices_prefix_len_str() {
        let a = &["c", "d", "a", "b", "c"];
        let b = &["x", "y", "z", "a", "b", "c"];
        let opt = slices_prefix_len(3, a, b);
        assert_eq!(opt, Some((2, 3)));
    }

    #[test]
    fn test_slices_prefix_len_equal() {
        let a = &["a", "b", "c"];
        let b = &["a", "b", "c"];
        let opt = slices_prefix_len(3, a, b);
        assert_eq!(opt, Some((0, 0)));
    }

    #[test]
    fn test_slices_prefix_len_u8() {
        let a = &[9, 0, 12, 1, 2, 3, 4, 5, 6];
        let b = &[0, 0, 2, 2, 3, 1, 4, 1, 2, 3, 4, 5];
        let opt = slices_prefix_len(4, a, b);
        assert_eq!(opt, Some((3, 7)));
    }

    #[test]
    fn test_slices_prefix_len_different() {
        let a = &[9, 0, 12, 1, 2, 5, 4, 5, 7];
        let b = &[0, 0, 2, 2, 3, 1, 4, 0, 3, 3, 5, 5];
        let opt = slices_prefix_len(4, a, b);
        assert!(opt.is_none());
    }
}
