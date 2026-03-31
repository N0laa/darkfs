use rand::RngCore;
use tempfile::NamedTempFile;
use darkfs::store::image::ImageFile;
use darkfs::util::constants::BLOCK_SIZE;

/// Create a temporary image file filled with random data, simulating `mkdark`.
pub fn create_random_image(num_blocks: u64) -> (NamedTempFile, ImageFile) {
    let tmp = NamedTempFile::new().expect("create tempfile");
    let size = num_blocks * BLOCK_SIZE as u64;
    let mut buf = vec![0u8; size as usize];
    rand::thread_rng().fill_bytes(&mut buf);
    std::io::Write::write_all(&mut tmp.as_file(), &buf).unwrap();
    let img = ImageFile::open(tmp.path()).unwrap();
    (tmp, img)
}
