mod checker;
mod export;
mod extract;
mod result;
mod custom_sites;
mod server;
mod sites;
#[cfg(feature = "vault")]
mod vault;

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!();
    println!("  \x1b[36m######  ##  ## ###### ##### ##    ####   #### ##  ##\x1b[0m");
    println!("  \x1b[36m##      ##  ## ##     ##  # ##   ##  ## ##    ## ##\x1b[0m");
    println!("  \x1b[36m######  ###### ####   ####  ##   ##  ## ##    ####\x1b[0m");
    println!("  \x1b[36m    ## ##  ## ##     ## ## ##   ##  ## ##    ## ##\x1b[0m");
    println!("  \x1b[36m###### ##  ## ###### ##  # ##### ####   #### ##  ##\x1b[0m");
    println!("  \x1b[90m────────────────── RS Edition v1.0.0 ──────────────────\x1b[0m");
    println!("  \x1b[90m  Author: Olivier Hoarau <tarraw974@gmail.com>\x1b[0m");
    println!();

    let state = Arc::new(server::AppState::new());

    // Load sites database in background
    let state_clone = state.clone();
    tokio::spawn(async move {
        print!("  Loading sites database... ");
        match sites::load_sites().await {
            Ok(s) => {
                let count = s.len();
                *state_clone.sites.write().await = Some(Arc::new(s));
                println!("\x1b[32m{} sites loaded\x1b[0m", count);
            }
            Err(e) => {
                println!("\x1b[31mFailed: {}\x1b[0m", e);
                *state_clone.load_error.write().await = Some(e.to_string());
            }
        }
    });

    // Idle auto-lock: tick every 60s; if the vault has been idle past its
    // configured timeout (default 30 min) the key + connection are dropped
    // and the user must re-enter the passphrase.
    #[cfg(feature = "vault")]
    {
        let vault = state.vault.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                if vault.maybe_auto_lock().await {
                    eprintln!("  \x1b[90m vault auto-locked (idle)\x1b[0m");
                }
            }
        });
    }

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let url = format!("http://127.0.0.1:{}", port);
    println!("  \x1b[32m Server:  {url}\x1b[0m");
    println!("  \x1b[90m Press Ctrl+C to stop\x1b[0m");
    #[cfg(target_os = "android")]
    println!("  \x1b[33m ↑ Open this URL in Chrome / Firefox on your phone ↑\x1b[0m");
    println!();

    // Open browser. On Android (Termux) `xdg-open` doesn't exist, so we
    // route through `termux-open-url` from the optional `termux-api`
    // package. Failure is non-fatal — the URL above is already printed.
    open_browser(&url);

    let app = server::create_router(state);
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(target_os = "android")]
fn open_browser(url: &str) {
    let _ = std::process::Command::new("termux-open-url")
        .arg(url)
        .status();
}

#[cfg(not(target_os = "android"))]
fn open_browser(url: &str) {
    let _ = open::that(url);
}
