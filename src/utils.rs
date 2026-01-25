use rand::seq::SliceRandom;
use rquest::Proxy;

pub struct UserAgentRotator {
    agents: Vec<String>,
}

impl UserAgentRotator {
    pub fn new() -> Self {
        UserAgentRotator {
            agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36".to_string(),
            ]
        }
    }
    
    #[allow(dead_code)]
    pub fn from_list(list: Vec<String>) -> Self {
        UserAgentRotator { agents: list }
    }

    pub fn get_random(&self) -> String {
        let mut rng = rand::thread_rng();
        self.agents.choose(&mut rng).cloned().unwrap_or_else(|| "RustSQLi-Hunter/2.0".to_string())
    }
}

pub struct ProxyManager {
    proxies: Vec<String>,
    current_index: usize,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>) -> Self {
        ProxyManager {
            proxies,
            current_index: 0,
        }
    }

    pub fn get_next(&mut self) -> Option<Proxy> {
        if self.proxies.is_empty() {
            return None;
        }
        
        // Simple rotation
        let proxy_url = &self.proxies[self.current_index];
        self.current_index = (self.current_index + 1) % self.proxies.len();
        
        match Proxy::all(proxy_url) {
            Ok(p) => Some(p),
            Err(_) => None, 
        }
    }
    
    #[allow(dead_code)]
    pub fn get_current_url(&self) -> Option<String> {
        if self.proxies.is_empty() {
            None
        } else {
            let idx = if self.current_index == 0 { self.proxies.len() - 1 } else { self.current_index - 1 };
            Some(self.proxies[idx].clone())
        }
    }
    
    #[allow(dead_code)]
    pub fn has_proxies(&self) -> bool {
        !self.proxies.is_empty()
    }
}
