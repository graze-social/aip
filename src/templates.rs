//! Minijinja template engine configuration with embedded and auto-reload modes.

#[cfg(feature = "reload")]
use minijinja_autoreload::AutoReloader;

#[cfg(feature = "embed")]
use minijinja::Environment;

#[cfg(feature = "reload")]
/// Build template environment with auto-reloading for development
pub fn build_env() -> AutoReloader {
    reload_env::build_env()
}

#[cfg(feature = "embed")]
/// Build template environment with embedded templates for production
pub fn build_env(http_external: String, version: String) -> Environment<'static> {
    embed_env::build_env(http_external, version)
}

#[cfg(feature = "reload")]
mod reload_env {
    use std::{env, path::PathBuf};

    use minijinja::{Environment, path_loader};
    use minijinja_autoreload::AutoReloader;

    pub fn build_env() -> AutoReloader {
        AutoReloader::new(move |notifier| {
            let template_path = if let Ok(value) = env::var("HTTP_TEMPLATE_PATH") {
                value.to_string()
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("templates")
                    .display()
                    .to_string()
            };
            let mut env = Environment::new();
            env.set_trim_blocks(true);
            env.set_lstrip_blocks(true);
            env.set_loader(path_loader(&template_path));
            notifier.set_fast_reload(true);
            notifier.watch_path(&template_path, true);
            Ok(env)
        })
    }
}

#[cfg(feature = "embed")]
mod embed_env {
    use minijinja::Environment;
    use std::path::PathBuf;

    pub fn build_env(http_external: String, version: String) -> Environment<'static> {
        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_global("base", format!("https://{}", http_external));
        env.add_global("version", version.clone());
        minijinja_embed::load_templates!(&mut env);
        env
    }
}
