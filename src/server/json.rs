use super::*;

type InputStreams = std::collections::HashMap<(u32, u32), tokio::sync::mpsc::Sender<Vec<u8>>>;
type TerminalResizes =
    std::collections::HashMap<u32, std::sync::mpsc::Sender<crate::worker::TerminalSize>>;
type StreamRequest = (Request, InputStreams, TerminalResizes);

pub(super) fn convert_json_request(
    v: &Value,
    state: &ServerState,
) -> Result<Request, (StatusCode, String)> {
    convert_json_request_with_stream(v, state, None).map(|(request, _, _)| request)
}
pub(super) fn convert_json_request_with_stream(
    v: &Value,
    state: &ServerState,
    output: Option<tokio::sync::mpsc::Sender<crate::worker::StreamOutput>>,
) -> Result<StreamRequest, (StatusCode, String)> {
    validate_json_request_types(v).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let cmds = match v.get("cmd") {
        Some(Value::Array(cmds)) => cmds,
        None | Some(Value::Null) => {
            return Err((StatusCode::BAD_REQUEST, "no cmd provided".into()));
        }
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid cmd: expected an array".into(),
            ));
        }
    };
    if cmds.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "no cmd provided".into()));
    }
    let mut req = Request {
        request_id: v
            .get("requestId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ..Request::default()
    };
    let mut inputs = std::collections::HashMap::new();
    let mut resizes = std::collections::HashMap::new();
    for (index, c) in cmds.iter().enumerate() {
        let mut cmd = Command {
            args: strings(c, "args"),
            env: strings(c, "env"),
            cpu_limit: Duration::from_nanos(num(c, "cpuLimit")),
            ..Command::default()
        };
        let real_cpu_limit = num(c, "realCpuLimit");
        cmd.clock_limit = Duration::from_nanos(if real_cpu_limit > 0 {
            real_cpu_limit
        } else {
            num(c, "clockLimit")
        });
        cmd.memory_limit = Size(num(c, "memoryLimit"));
        cmd.stack_limit = Size(num(c, "stackLimit"));
        cmd.output_limit = Size(state.config.output_limit.0);
        cmd.proc_limit = num(c, "procLimit");
        cmd.cpu_rate_limit = num(c, "cpuRateLimit");
        cmd.cpu_set_limit = text(c, "cpuSetLimit");
        cmd.copy_out_max = num(c, "copyOutMax");
        cmd.copy_out_truncate = boolv(c, "copyOutTruncate");
        cmd.tty = boolv(c, "tty");
        if cmd.tty {
            let (tx, rx) = std::sync::mpsc::channel();
            cmd.terminal_resize = Some(Arc::new(std::sync::Mutex::new(rx)));
            resizes.insert(index as u32, tx);
        }
        cmd.data_segment_limit = boolv(c, "dataSegmentLimit") || boolv(c, "strictMemoryLimit");
        cmd.address_space_limit = boolv(c, "addressSpaceLimit");
        if let Some(fs) = c.get("files").and_then(Value::as_array) {
            for (fd, f) in fs.iter().enumerate() {
                if boolv(f, "streamIn") {
                    let (tx, rx) = tokio::sync::mpsc::channel(8);
                    inputs.insert((index as u32, fd as u32), tx);
                    cmd.files
                        .push(CmdFile::StreamIn(Arc::new(std::sync::Mutex::new(rx))));
                } else if boolv(f, "streamOut") {
                    let Some(output) = output.as_ref() else {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            "streamOut is only valid on /stream".into(),
                        ));
                    };
                    cmd.files.push(CmdFile::StreamOut {
                        index: index as u32,
                        fd: fd as u32,
                        tx: output.clone(),
                    });
                } else {
                    cmd.files.push(convert_cmd_file(f, state)?);
                }
            }
        }
        if let Some(map) = c.get("copyIn").and_then(Value::as_object) {
            for (name, f) in map {
                if let Some(target) = f.get("symlink").and_then(Value::as_str) {
                    cmd.symlinks.insert(name.clone(), target.to_owned());
                    continue;
                }
                match convert_cmd_file(f, state)? {
                    CmdFile::Local(p) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Local(p));
                    }
                    CmdFile::Memory(b) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Memory(b));
                    }
                    CmdFile::Cached(id) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Cached(id));
                    }
                    other => {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            format!("unsupported copyIn source {other}"),
                        ));
                    }
                }
            }
        }
        cmd.copy_out = copyouts(c, "copyOut");
        cmd.copy_out_cached = copyouts(c, "copyOutCached");
        req.commands.push(cmd);
    }
    if let Some(maps) = v.get("pipeMapping").and_then(Value::as_array) {
        for m in maps {
            let idx = |k: &str| {
                let x = &m[k];
                PipeIndex {
                    index: x["index"].as_u64().unwrap_or(0) as usize,
                    fd: x["fd"].as_u64().unwrap_or(0) as usize,
                }
            };
            req.pipe_mapping.push(PipeMap {
                input: idx("in"),
                output: idx("out"),
                cpu_set: text(m, "cpuSet"),
                name: text(m, "name"),
                // Go's JSON model decodes PipeMap.max as int64, then casts
                // it to the unsigned environment size type.
                limit: Size(signed_num(m, "max") as u64),
                proxy: boolv(m, "proxy"),
                disable_zero_copy: boolv(m, "disableZeroCopy"),
            });
        }
    }
    Ok((req, inputs, resizes))
}

pub(super) fn validate_json_request_types(value: &Value) -> Result<(), String> {
    fn type_name(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
    fn field<F>(object: &Value, key: &str, expected: &str, predicate: F) -> Result<(), String>
    where
        F: FnOnce(&Value) -> bool,
    {
        let Some(value) = object.get(key) else {
            return Ok(());
        };
        if value.is_null() || predicate(value) {
            Ok(())
        } else {
            Err(format!(
                "json: cannot unmarshal {} into Go struct field {key} of type {expected}",
                type_name(value)
            ))
        }
    }
    fn string_array(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "[]string", |value| {
            value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        })
    }
    fn string_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "string", Value::is_string)
    }
    fn bool_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "bool", Value::is_boolean)
    }
    fn uint_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "uint64", |value| value.as_u64().is_some())
    }
    fn int_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "int64", |value| value.as_i64().is_some())
    }
    fn object_fields<F>(value: &Value, what: &str, validate: F) -> Result<(), String>
    where
        F: FnOnce(&Value) -> Result<(), String>,
    {
        if value.is_null() || value.is_object() {
            if value.is_object() {
                validate(value)
            } else {
                Ok(())
            }
        } else {
            Err(format!(
                "json: cannot unmarshal {} into Go struct field {what}",
                type_name(value)
            ))
        }
    }
    fn validate_file(file: &Value) -> Result<(), String> {
        object_fields(file, "CmdFile", |file| {
            for key in ["src", "content", "fileId", "name", "symlink"] {
                string_field(file, key)?;
            }
            int_field(file, "max")?;
            for key in ["streamIn", "streamOut", "pipe"] {
                bool_field(file, key)?;
            }
            Ok(())
        })
    }

    if !value.is_object() && !value.is_null() {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type model.Request",
            type_name(value)
        ));
    }
    string_field(value, "requestId")?;
    field(value, "cmd", "[]model.Cmd", Value::is_array)?;
    field(value, "pipeMapping", "[]model.PipeMap", Value::is_array)?;
    if let Some(commands) = value.get("cmd").and_then(Value::as_array) {
        for command in commands {
            object_fields(command, "Cmd", |command| {
                for key in ["args", "env", "copyOut", "copyOutCached"] {
                    string_array(command, key)?;
                }
                for key in [
                    "cpuLimit",
                    "realCpuLimit",
                    "clockLimit",
                    "memoryLimit",
                    "stackLimit",
                    "procLimit",
                    "cpuRateLimit",
                    "copyOutMax",
                ] {
                    uint_field(command, key)?;
                }
                for key in ["cpuSetLimit", "copyOutDir"] {
                    string_field(command, key)?;
                }
                for key in [
                    "copyOutTruncate",
                    "tty",
                    "strictMemoryLimit",
                    "dataSegmentLimit",
                    "addressSpaceLimit",
                ] {
                    bool_field(command, key)?;
                }
                if let Some(files) = command.get("files") {
                    field(command, "files", "[]*CmdFile", Value::is_array)?;
                    if let Some(files) = files.as_array() {
                        for file in files {
                            validate_file(file)?;
                        }
                    }
                }
                if let Some(copy_in) = command.get("copyIn") {
                    field(command, "copyIn", "map[string]CmdFile", Value::is_object)?;
                    if let Some(copy_in) = copy_in.as_object() {
                        for file in copy_in.values() {
                            validate_file(file)?;
                        }
                    }
                }
                Ok(())
            })?;
        }
    }
    if let Some(mappings) = value.get("pipeMapping").and_then(Value::as_array) {
        for mapping in mappings {
            object_fields(mapping, "PipeMap", |mapping| {
                {
                    let key = "name";
                    string_field(mapping, key)?;
                }
                int_field(mapping, "max")?;
                for key in ["proxy", "disableZeroCopy"] {
                    bool_field(mapping, key)?;
                }
                for key in ["in", "out"] {
                    if let Some(index) = mapping.get(key) {
                        object_fields(index, "PipeIndex", |index| {
                            for component in ["index", "fd"] {
                                field(index, component, "int", |value| value.as_i64().is_some())?;
                            }
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

pub(super) fn convert_cmd_file(
    v: &Value,
    state: &ServerState,
) -> Result<CmdFile, (StatusCode, String)> {
    if v.is_null() {
        return Ok(CmdFile::Null);
    }
    if let Some(s) = v.get("src").and_then(Value::as_str) {
        let p = PathBuf::from(s);
        if let Some(error) = source_path_error(&p, &state.config.src_prefix) {
            return Err(error);
        }
        return Ok(CmdFile::Local(p));
    }
    if let Some(s) = v.get("content").and_then(Value::as_str) {
        return Ok(CmdFile::Memory(s.as_bytes().to_vec()));
    }
    if let Some(s) = v.get("fileId").and_then(Value::as_str) {
        if state.files.get(s).is_none() {
            return Err((
                StatusCode::NOT_FOUND,
                format!("file does not exist with id {s:?}"),
            ));
        }
        return Ok(CmdFile::Cached(s.into()));
    }
    if let (Some(name), Some(max)) = (
        v.get("name").and_then(Value::as_str),
        v.get("max").and_then(Value::as_i64),
    ) {
        return Ok(CmdFile::Collector {
            name: name.to_owned(),
            // Match Go's int64-to-Size conversion for negative max values.
            max: Size(max as u64),
            pipe: boolv(v, "pipe"),
        });
    }
    if v.get("symlink").is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "symlink entries require the copyIn map form".into(),
        ));
    }
    Err((StatusCode::BAD_REQUEST, "invalid command file".into()))
}

pub(super) fn source_path_allowed(path: &std::path::Path, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    let Some(source) = resolve_source_path(path) else {
        return false;
    };
    prefixes.iter().any(|prefix| {
        resolve_source_path(std::path::Path::new(prefix))
            .is_some_and(|prefix| source.starts_with(prefix))
    })
}

pub(super) fn source_path_error(
    path: &std::path::Path,
    prefixes: &[String],
) -> Option<(StatusCode, String)> {
    if path.as_os_str().is_empty() {
        return Some((StatusCode::BAD_REQUEST, "source path is empty".into()));
    }
    if !source_path_allowed(path, prefixes) {
        return Some((
            StatusCode::BAD_REQUEST,
            format!(
                "file ({}) does not under ([{}])",
                path.display(),
                prefixes.join(" ")
            ),
        ));
    }
    if !path.exists() {
        return Some((
            StatusCode::NOT_FOUND,
            format!(
                "source file does not exist {:?}: file not found",
                path.display()
            ),
        ));
    }
    None
}

/// Resolve existing symlinks and preserve a missing suffix, matching Go's
/// source-prefix check. This keeps missing files under an allowed prefix
/// distinguishable from missing paths outside it.
pub(super) fn resolve_source_path(path: &std::path::Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut cursor = absolute;
    let mut suffix = Vec::new();
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(&cursor) {
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        let name = cursor.file_name()?.to_os_string();
        suffix.push(name);
        if !cursor.pop() {
            return None;
        }
    }
}

pub(super) fn strings(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
pub(super) fn num(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}
pub(super) fn signed_num(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or(0)
}
pub(super) fn boolv(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}
pub(super) fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
pub(super) fn copyouts(v: &Value, k: &str) -> Vec<CopyOutFile> {
    strings(v, k)
        .into_iter()
        .map(|n| {
            let optional = n.ends_with('?');
            CopyOutFile {
                name: if optional {
                    n[..n.len() - 1].to_owned()
                } else {
                    n
                },
                optional,
            }
        })
        .collect()
}
pub(super) fn mime_guess(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "log" | "go" | "rs" | "c" | "cpp" | "h" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        _ => "application/octet-stream",
    }
}
