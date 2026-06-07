use std::{
    env, fs,
    io::{self, Write},
    path::Path,
    process,
};

const ABO_MAGIC: [u8; 4] = *b"ABO\0";
const ABO_VERSION_MAJ: u16 = 0;
const ABO_VERSION_MIN: u16 = 0;
const ABO_HEADER_SIZE: usize = 64;
const ABO_SEGMENT_SIZE: usize  = 32;

const ABO_FLAG_NATIVE: u32 = 1 << 0;
const ABO_FLAG_WASM: u32 = 1 << 1;

const ABO_SEG_R: u32 = 1 << 0;
const ABO_SEG_W: u32 = 1 << 1;
const ABO_SEG_X: u32 = 1 << 2;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;


#[derive(Debug)]
struct ElfInfo {
    e_type: u16,
    e_entry: u64,
    segments: Vec<ElfSegment>,
}

#[derive(Debug)]
struct ElfSegment {
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Debug)]
struct AboSegment {
    vaddr: u64,
    mem_size: u64,
    file_off: u64,
    file_size: u32,
    flags: u32,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct Manifest {
    name: String,
    version: String,
    caps_req: Vec<String>,
    caps_exp: Vec<String>,
    sandbox: Vec<String>,
}

impl Manifest {
    fn parse(text: &str) -> Self {
        let mut m = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some(v) = line.strip_prefix("NAME=") { m.name = v.to_string(); }
            if let Some(v) = line.strip_prefix("VERSION=") { m.version = v.to_string(); }
            if let Some(v) = line.strip_prefix("CAP_REQ=") { m.caps_req.push(v.to_string()); }
            if let Some(v) = line.strip_prefix("CAP_EXP=") { m.caps_exp.push(v.to_string()); }
            if let Some(v) = line.strip_prefix("SANDBOX=") { m.sandbox.push(v.to_string()); }
        }
        m
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = String::new();
        if !self.name.is_empty() { out.push_str(&format!("NAME={}\n",    self.name)); }
        if !self.version.is_empty() { out.push_str(&format!("VERSION={}\n", self.version)); }
        for c in &self.caps_req { out.push_str(&format!("CAP_REQ={}\n", c)); }
        for c in &self.caps_exp { out.push_str(&format!("CAP_EXP={}\n", c)); }
        for s in &self.sandbox  { out.push_str(&format!("SANDBOX={}\n", s)); }
        out.into_bytes()
    }
}

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off+2].try_into().unwrap())
}
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off+4].try_into().unwrap())
}
fn read_u64_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off+8].try_into().unwrap())
}

fn parse_elf(data: &[u8]) -> Result<ElfInfo, String> {
    if data.len() < 64 {
        return Err("File too small to be ELF".into());
    }

    if &data[0..4] != &ELF_MAGIC {
        return Err(format!("Bad ELF magic: {:?}", &data[0..4]));
    }
    if data[4] != ELFCLASS64  { return Err("Not ELF64".into()); }
    if data[5] != ELFDATA2LSB { return Err("Not little-endian".into()); }

    let e_type= read_u16_le(data, 16);
    let e_machine= read_u16_le(data, 18);
    let e_entry= read_u64_le(data, 24);
    let e_phoff= read_u64_le(data, 32) as usize;
    let e_phnum= read_u16_le(data, 56) as usize;
    let e_phentsize= read_u16_le(data, 54) as usize;

    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(format!("Not an executable ELF (type={})", e_type));
    }
    if e_machine != EM_X86_64 {
        return Err(format!("Not x86_64 (machine={})", e_machine));
    }
    if e_phentsize < 56 {
        return Err("Program header entry too small".into());
    }

    let mut segments= Vec::new();

    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 56 > data.len() {
            return Err(format!("Program header {} out of file", i));
        }

        let p_type= read_u32_le(data, off);
        let p_flags= read_u32_le(data, off + 4);
        let p_offset= read_u64_le(data, off + 8);
        let p_vaddr= read_u64_le(data, off + 16);
        let p_filesz= read_u64_le(data, off + 32);
        let p_memsz= read_u64_le(data, off + 40);

        if p_type != PT_LOAD { continue; }
        if p_memsz == 0 { continue; }

        let file_end = p_offset as usize + p_filesz as usize;
        if file_end > data.len() {
            return Err(format!("Segment {} exceeds file size", i));
        }

        segments.push(ElfSegment { p_flags, p_offset, p_vaddr, p_filesz, p_memsz });
    }

    if segments.is_empty() {
        return Err("No PT_LOAD segments found".into());
    }

    Ok(ElfInfo { e_type, e_entry, segments })
}

fn build_abo(
    elf_data: &[u8],
    elf: &ElfInfo,
    manifest: &Manifest,
    uuid: [u8; 16],
) -> Result<Vec<u8>, String> {

    let load_bias: u64 = if elf.e_type == ET_DYN {
        0x0040_0000
    } else {
        0
    };
    let mut abo_segs: Vec<AboSegment> = Vec::new();
    let mut entry_vaddr = elf.e_entry.wrapping_add(load_bias);
    let mut first_exec_seg: Option<usize> = None;

    for (i, seg) in elf.segments.iter().enumerate() {
        let vaddr = seg.p_vaddr.wrapping_add(load_bias);

        let mut flags = ABO_SEG_R;
        if seg.p_flags & PF_W != 0 { flags |= ABO_SEG_W; }
        if seg.p_flags & PF_X != 0 {
            flags |= ABO_SEG_X;
            if first_exec_seg.is_none() { first_exec_seg = Some(i); }
        }

        let file_start= seg.p_offset as usize;
        let file_end= file_start + seg.p_filesz as usize;
        let data = elf_data[file_start..file_end].to_vec();

        abo_segs.push(AboSegment {
            vaddr,
            mem_size: seg.p_memsz,
            file_off: 0,
            file_size: seg.p_filesz as u32,
            flags,
            data,
        });
    }

    if entry_vaddr == 0 {
        return Err("Entry point is null".into());
    }

    let entry_offset: u32 = if let Some(idx) = first_exec_seg {
        let seg_vaddr = abo_segs[idx].vaddr;
        if entry_vaddr < seg_vaddr {
            return Err(format!(
                "Entry point 0x{:x} is before first exec segment 0x{:x}",
                entry_vaddr, seg_vaddr
            ));
        }
        (entry_vaddr - seg_vaddr) as u32
    } else {
        return Err("No executable segment found".into());
    };

    let manifest_bytes = manifest.serialize();

    let n_segs = abo_segs.len();
    let manifest_off= ABO_HEADER_SIZE as u32;
    let manifest_size= manifest_bytes.len() as u32;
    let segments_tab_off = ABO_HEADER_SIZE + manifest_bytes.len();
    let segments_data_off = segments_tab_off + n_segs * ABO_SEGMENT_SIZE;

    let mut data_cursor = segments_data_off as u64;
    for seg in abo_segs.iter_mut() {
        seg.file_off = data_cursor;
        data_cursor += seg.file_size as u64;
    }

    let total_size = data_cursor as usize;
    let mut out = vec![0u8; total_size];

    out[0..4].copy_from_slice(&ABO_MAGIC);
    out[4..6].copy_from_slice(&ABO_VERSION_MAJ.to_le_bytes());
    out[6..8].copy_from_slice(&ABO_VERSION_MIN.to_le_bytes());
    out[8..24].copy_from_slice(&uuid);
    let flags = ABO_FLAG_NATIVE;
    out[24..28].copy_from_slice(&flags.to_le_bytes());
    out[28..32].copy_from_slice(&manifest_off.to_le_bytes());
    out[32..36].copy_from_slice(&manifest_size.to_le_bytes());
    out[36..40].copy_from_slice(&(segments_tab_off as u32).to_le_bytes());
    out[40..44].copy_from_slice(&(n_segs as u32).to_le_bytes());
    out[44..48].copy_from_slice(&entry_offset.to_le_bytes());

    let ms = manifest_bytes.len();
    out[ABO_HEADER_SIZE..ABO_HEADER_SIZE + ms].copy_from_slice(&manifest_bytes);

    for (i, seg) in abo_segs.iter().enumerate() {
        let tab_off = segments_tab_off + i * ABO_SEGMENT_SIZE;
        out[tab_off..tab_off+8].copy_from_slice(&seg.vaddr.to_le_bytes());
        out[tab_off+8..tab_off+16].copy_from_slice(&seg.mem_size.to_le_bytes());
        out[tab_off+16..tab_off+24].copy_from_slice(&seg.file_off.to_le_bytes());
        out[tab_off+24..tab_off+28].copy_from_slice(&seg.file_size.to_le_bytes());
        out[tab_off+28..tab_off+32].copy_from_slice(&seg.flags.to_le_bytes());
    }

    for seg in &abo_segs {
        let off = seg.file_off as usize;
        out[off..off + seg.data.len()].copy_from_slice(&seg.data);
    }

    Ok(out)
}


fn cmd_build(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("Usage: abo-builder <input.elf> <output.abo> [--manifest <file>] [--name <name>] [--cap-req <cap>]".into());
    }

    let input  = &args[0];
    let output = &args[1];

    let mut manifest_file: Option<String> = None;
    let mut manifest = Manifest::default();
    manifest.name    = Path::new(input)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    manifest.version = "0.1.0".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                if i >= args.len() { return Err("--manifest needs a file".into()); }
                manifest_file = Some(args[i].clone());
            }
            "--name" => {
                i += 1;
                if i >= args.len() { return Err("--name needs a value".into()); }
                manifest.name = args[i].clone();
            }
            "--version" => {
                i += 1;
                if i >= args.len() { return Err("--version needs a value".into()); }
                manifest.version = args[i].clone();
            }
            "--cap-req" => {
                i += 1;
                if i >= args.len() { return Err("--cap-req needs a value".into()); }
                manifest.caps_req.push(args[i].clone());
            }
            "--cap-exp" => {
                i += 1;
                if i >= args.len() { return Err("--cap-exp needs a value".into()); }
                manifest.caps_exp.push(args[i].clone());
            }
            "--sandbox" => {
                i += 1;
                if i >= args.len() { return Err("--sandbox needs a value".into()); }
                manifest.sandbox.push(args[i].clone());
            }
            other => return Err(format!("Unknown option: {}", other)),
        }
        i += 1;
    }

    if let Some(mf) = manifest_file {
        let text = fs::read_to_string(&mf)
            .map_err(|e| format!("Cannot read manifest {}: {}", mf, e))?;
        manifest = Manifest::parse(&text);
    }

    let elf_data = fs::read(input)
        .map_err(|e| format!("Cannot read {}: {}", input, e))?;

    let elf = parse_elf(&elf_data)
        .map_err(|e| format!("ELF parse error: {}", e))?;

    println!("ELF: {} segments, entry=0x{:x}, type={}",
             elf.segments.len(), elf.e_entry,
             if elf.e_type == ET_DYN { "PIE" } else { "EXEC" }
    );

    for (i, seg) in elf.segments.iter().enumerate() {
        let flags_str = format!("{}{}{}",
            if seg.p_flags & PF_R != 0 { "R" } else { "-" },
            if seg.p_flags & PF_W != 0 { "W" } else { "-" },
             if seg.p_flags & PF_X != 0 { "X" } else { "-" },
        );
        println!("  Segment {}: vaddr=0x{:08x} filesz={:6} memsz={:6} [{}]",
                 i, seg.p_vaddr, seg.p_filesz, seg.p_memsz, flags_str);
    }

    let uuid = name_to_uuid(&manifest.name);

    let abo_data = build_abo(&elf_data, &elf, &manifest, uuid)
        .map_err(|e| format!("ABO build error: {}", e))?;

    fs::write(output, &abo_data)
        .map_err(|e| format!("Cannot write {}: {}", output, e))?;

    println!("ABO: {} bytes → {}", abo_data.len(), output);
    println!("  UUID: {}", format_uuid(&uuid));
    println!("  Name: {}", manifest.name);
    println!("  Segments: {}", elf.segments.len());

    Ok(())
}

fn cmd_check(path: &str) -> Result<(), String> {
    let data = fs::read(path)
        .map_err(|e| format!("Cannot read {}: {}", path, e))?;

    if data.len() < ABO_HEADER_SIZE {
        return Err("File too small".into());
    }
    if &data[0..4] != &ABO_MAGIC {
        return Err(format!("Bad magic: {:?}", &data[0..4]));
    }

    let ver_maj = u16::from_le_bytes(data[4..6].try_into().unwrap());
    if ver_maj != ABO_VERSION_MAJ {
        return Err(format!("Unsupported version: {}", ver_maj));
    }

    println!("ABO OK: {} ({} bytes)", path, data.len());
    Ok(())
}

fn cmd_dump(path: &str) -> Result<(), String> {
    let data = fs::read(path)
        .map_err(|e| format!("Cannot read {}: {}", path, e))?;

    if data.len() < ABO_HEADER_SIZE {
        return Err("File too small".into());
    }
    if &data[0..4] != &ABO_MAGIC {
        return Err("Bad magic".into());
    }

    let ver_maj= u16::from_le_bytes(data[4..6].try_into().unwrap());
    let ver_min= u16::from_le_bytes(data[6..8].try_into().unwrap());
    let uuid: [u8;16] = data[8..24].try_into().unwrap();
    let flags= u32::from_le_bytes(data[24..28].try_into().unwrap());
    let manifest_off = u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize;
    let manifest_sz= u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
    let segs_off= u32::from_le_bytes(data[36..40].try_into().unwrap()) as usize;
    let segs_count= u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize;
    let entry_off= u32::from_le_bytes(data[44..48].try_into().unwrap());

    println!("⟾ ✵✵✵⨑ ABO Header ∱✵✵✵ ⟽");
    println!("  Version   : {}.{}", ver_maj, ver_min);
    println!("  UUID      : {}", format_uuid(&uuid));
    println!("  Flags     : 0x{:08x} ({}{})",
             flags,
             if flags & ABO_FLAG_NATIVE != 0 { "NATIVE " } else { "" },
             if flags & ABO_FLAG_WASM   != 0 { "WASM"    } else { "" },
    );
    println!("  Entry off : 0x{:x}", entry_off);
    println!("  Segments  : {}", segs_count);

    if manifest_sz > 0 && manifest_off + manifest_sz <= data.len() {
        println!("\n⟾ ✵✵✵⨑ manifest ∱✵✵✵ ⟽");
        if let Ok(text) = std::str::from_utf8(&data[manifest_off..manifest_off+manifest_sz]) {
            for line in text.lines() {
                println!("  {}", line);
            }
        }
    }

    println!("\n⟾ ✵✵✵⨑ Segments ∱✵✵✵ ⟽");
    for i in 0..segs_count {
        let off = segs_off + i * ABO_SEGMENT_SIZE;
        if off + ABO_SEGMENT_SIZE > data.len() { break; }

        let vaddr = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let mem_size= u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let file_off= u64::from_le_bytes(data[off+16..off+24].try_into().unwrap());
        let file_size= u32::from_le_bytes(data[off+24..off+28].try_into().unwrap());
        let seg_flags= u32::from_le_bytes(data[off+28..off+32].try_into().unwrap());

        println!("  [{i}] vaddr=0x{:012x} mem={:8} file={:8}@0x{:x} [{}{}{}]",
                 vaddr, mem_size, file_size, file_off,
                 if seg_flags & ABO_SEG_R != 0 { "R" } else { "-" },
                 if seg_flags & ABO_SEG_W != 0 { "W" } else { "-" },
                 if seg_flags & ABO_SEG_X != 0 { "X" } else { "-" },
        );
    }

    Ok(())
}

fn name_to_uuid(name: &str) -> [u8; 16] {
    let mut uuid = [0u8; 16];
    uuid[0] = 0x41; // 'A'
    uuid[1] = 0x73; // 's'
    uuid[2] = 0x74; // 't'
    uuid[3] = 0x65; // 'e'
    let mut h: u64 = 0x1234_5678_9ABC_DEF0;
    for b in name.bytes() {
        h = h.wrapping_mul(0x100_0000_01B3).wrapping_add(b as u64);
    }
    uuid[4..12].copy_from_slice(&h.to_le_bytes());
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],uuid[1],uuid[2],uuid[3],
        uuid[4],uuid[5],uuid[6],uuid[7],
        uuid[8],uuid[9],
        uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("abo-builder v0.1 ; Application/Annwyn Bundle Object builder");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  abo-builder <in.elf> <out.abo>    Convert ELF to ABO");
        eprintln!("    [--manifest <file>]              Manifest file (KEY=VALUE lines)");
        eprintln!("    [--name <name>]                  Component name");
        eprintln!("    [--version <semver>]             Component version");
        eprintln!("    [--cap-req <capability>]         Required capability (repeatable)");
        eprintln!("    [--cap-exp <service>]            Exposed service (repeatable)");
        eprintln!("    [--sandbox <restriction>]        Sandbox restriction (repeatable)");
        eprintln!();
        eprintln!("  abo-builder --check <file.abo>    Validate ABO header");
        eprintln!("  abo-builder --dump  <file.abo>    Dump ABO structure");
        eprintln!();
        eprintln!("Manifest format (one directive per line):");
        eprintln!("  NAME=init");
        eprintln!("  VERSION=0.1.0");
        eprintln!("  CAP_REQ=IpcEndpoint:SEND");
        eprintln!("  CAP_EXP=service://init");
        eprintln!("  SANDBOX=no_network");
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "--check" if args.len() >= 3 => cmd_check(&args[2]),
        "--dump"  if args.len() >= 3 => cmd_dump(&args[2]),
        "--check" | "--dump"=> Err("Missing file argument".into()),
        _ => cmd_build(&args[1..]),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}