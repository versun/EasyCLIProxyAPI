use super::*;

pub(crate) async fn update_core_config(
    config: &GuiConfigFile,
    patch: serde_json::Value,
    fallback: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if !crate::management_api::patch_management_config_if_available(config, &patch).await? {
        fallback()?;
    }
    Ok(())
}

async fn rollback_core_config(
    config: &GuiConfigFile,
    patch: serde_json::Value,
    fallback: impl FnOnce() -> Result<(), String>,
) -> Option<String> {
    match crate::management_api::patch_management_config_if_available(config, &patch).await {
        Ok(true) => None,
        Ok(false) => fallback().err(),
        Err(api_error) => fallback()
            .err()
            .map(|file_error| format!("{api_error}; {file_error}")),
    }
}

async fn current_core_config_settings_via_api(
    gui_config_state: &GuiConfigState,
) -> Result<CoreConfigSettings, String> {
    let config = gui_config_state.snapshot()?;
    if let Some(value) =
        crate::management_api::fetch_management_config_if_available(&config).await?
    {
        let document = serde_norway::to_value(value)
            .map_err(|error| format!("Failed to parse kernel configuration: {error}"))?;
        core_config_settings_from_value(&document)
    } else {
        current_core_config_settings(gui_config_state)
    }
}

#[tauri::command]
pub(crate) fn get_lan_ipv4() -> Option<String> {
    detect_lan_ipv4().map(|address| address.to_string())
}

#[tauri::command]
pub(crate) async fn get_core_tls_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreTlsSettings, String> {
    let config = gui_config_state.snapshot()?;
    if let Some(value) =
        crate::management_api::fetch_management_config_if_available(&config).await?
    {
        let document = serde_norway::to_value(value)
            .map_err(|error| format!("Failed to parse kernel configuration: {error}"))?;
        core_tls_settings_from_value(&document)
    } else {
        current_core_tls_settings()
    }
}

#[tauri::command]
pub(crate) async fn save_core_tls_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    cache: tauri::State<'_, AgentConfigStatusCache>,
    settings: CoreTlsSettings,
) -> Result<CoreTlsSettings, String> {
    let settings = normalize_core_tls_settings(settings)?;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"server": {"tls": {"enable": settings.enabled, "cert": settings.cert, "key": settings.key}}}),
        || patch_core_tls_settings(&settings),
    )
    .await?;
    cache.clear()?;
    Ok(settings)
}

#[tauri::command]
pub(crate) async fn get_core_sensitive_words_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreSensitiveWordsSettings, String> {
    let config = gui_config_state.snapshot()?;
    if let Some(value) =
        crate::management_api::fetch_management_config_if_available(&config).await?
    {
        let document = serde_norway::to_value(value)
            .map_err(|error| format!("Failed to parse kernel configuration: {error}"))?;
        core_sensitive_words_settings_from_value(&document)
    } else {
        read_core_sensitive_words_settings()
    }
}

#[tauri::command]
pub(crate) async fn save_core_sensitive_words_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    settings: CoreSensitiveWordsSettings,
) -> Result<CoreSensitiveWordsSettings, String> {
    let normalized = normalize_core_sensitive_words_settings(settings);
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"oauth": {"providers": {
            "antigravity": {"sensitive-words": normalized.antigravity_sensitive_words},
            "devin": {"sensitive-words": normalized.devin_sensitive_words}
        }}}),
        || patch_core_sensitive_words_settings(&normalized),
    )
    .await?;
    Ok(normalized)
}

pub(crate) fn detect_lan_ipv4() -> Option<Ipv4Addr> {
    for target in ["192.0.2.1:80", "8.8.8.8:80"] {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(local_address) = socket.local_addr() else {
            continue;
        };
        let IpAddr::V4(address) = local_address.ip() else {
            continue;
        };
        if !address.is_unspecified() && !address.is_loopback() {
            return Some(address);
        }
    }
    None
}

#[tauri::command]
pub(crate) async fn save_gui_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    cache: tauri::State<'_, AgentConfigStatusCache>,
    settings: GuiNetworkSettings,
) -> Result<GuiSettings, String> {
    if settings.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }

    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.port = settings.port;
    next.allow_lan = settings.allow_lan;
    next.host = if settings.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    }
    .to_string();
    update_core_config(
        &previous,
        serde_json::json!({"server": {"host": next.host, "port": next.port}}),
        || patch_core_network_settings(&next),
    )
    .await?;
    let _refresh_guard = cache
        .refresh_lock
        .lock()
        .map_err(|_| "Agent configuration status refresh lock is poisoned".to_string())?;
    let config = match gui_config_state.update_network(settings.port, settings.allow_lan) {
        Ok(config) => config,
        Err(error) => {
            drop(_refresh_guard);
            let rollback_error = rollback_core_config(
                &next,
                serde_json::json!({"server": {"host": previous.host, "port": previous.port}}),
                || patch_core_network_settings(&previous),
            )
            .await;
            return Err(match rollback_error {
                Some(rollback_error) => {
                    format!("{error}; failed to roll back kernel network configuration: {rollback_error}")
                }
                None => error,
            });
        }
    };

    if config.port != previous.port {
        if let Err(error) = cache.clear() {
            eprintln!("Failed to clear agent configuration status cache: {error}");
        }
    }

    Ok(GuiSettings::from(&config))
}

#[tauri::command]
pub(crate) async fn save_network_routing_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    cache: tauri::State<'_, AgentConfigStatusCache>,
    settings: GuiNetworkRoutingSettings,
) -> Result<CoreConfigView, String> {
    if settings.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    let routing_session_affinity_ttl =
        normalize_session_affinity_ttl(settings.routing_session_affinity_ttl)?;

    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.port = settings.port;
    next.allow_lan = settings.allow_lan;
    next.host = if settings.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    }
    .to_string();
    next.routing_session_affinity = settings.routing_session_affinity;
    next.routing_session_affinity_ttl = routing_session_affinity_ttl.clone();
    next.disable_cooling = settings.disable_cooling;
    next.request_retry = settings.request_retry;
    next.max_retry_credentials = settings.max_retry_credentials;
    next.max_retry_interval = settings.max_retry_interval;
    next.streaming_bootstrap_retries = settings.streaming_bootstrap_retries;
    validate_gui_config(&next)?;

    let patch = |config: &GuiConfigFile| {
        serde_json::json!({
            "server": {"host": config.host, "port": config.port},
            "requests": {"proxy-url": config.proxy_url, "streaming": {"bootstrap-retries": config.streaming_bootstrap_retries}},
            "routing": {
                "session-affinity": config.routing_session_affinity,
                "session-affinity-ttl": config.routing_session_affinity_ttl,
                "cooldown": {"disable-cooling": config.disable_cooling},
                "retry": {
                    "request-retry": config.request_retry,
                    "max-retry-credentials": config.max_retry_credentials,
                    "max-retry-interval": config.max_retry_interval
                }
            }
        })
    };
    update_core_config(&previous, patch(&next), || {
        patch_core_network_routing_settings(&next)
    })
    .await?;
    let _refresh_guard = cache
        .refresh_lock
        .lock()
        .map_err(|_| "Agent configuration status refresh lock is poisoned".to_string())?;
    let config = match gui_config_state.update_network_routing(&next) {
        Ok(config) => config,
        Err(error) => {
            drop(_refresh_guard);
            let rollback_error = rollback_core_config(&next, patch(&previous), || {
                patch_core_network_routing_settings(&previous)
            })
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };

    if config.port != previous.port {
        if let Err(error) = cache.clear() {
            eprintln!("Failed to clear agent configuration status cache: {error}");
        }
    }

    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn save_network_endpoint_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    cache: tauri::State<'_, AgentConfigStatusCache>,
    settings: GuiNetworkEndpointSettings,
) -> Result<CoreConfigView, String> {
    if settings.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    let host = normalize_optional_config_string(settings.host, "Listen IP")?;
    if host.parse::<IpAddr>().is_err() {
        return Err("Listen IP must be a valid IPv4 or IPv6 address".to_string());
    }
    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.host = host;
    next.allow_lan = !is_loopback_host(&next.host);
    next.port = settings.port;
    if settings.proxy_url.is_some() || settings.proxy_override.is_some() {
        let proxy_url = network_proxy::normalize_optional_proxy_url(
            settings.proxy_url.as_deref().unwrap_or(&next.proxy_url),
        )?;
        // Explicit mode selection lets an empty manual URL mean direct access.
        // Calls from older frontends keep the legacy behavior where an empty URL
        // means following the system proxy.
        next.proxy_override = settings
            .proxy_override
            .unwrap_or_else(|| !proxy_url.is_empty());
        next.proxy_url = if next.proxy_override {
            proxy_url
        } else {
            network_proxy::detect()
        };
    }
    validate_gui_config(&next)?;
    let patch = |config: &GuiConfigFile| {
        serde_json::json!({
            "server": {"host": config.host, "port": config.port},
            "requests": {"proxy-url": config.proxy_url}
        })
    };
    update_core_config(&previous, patch(&next), || {
        patch_core_network_endpoint_settings(&next)
    })
    .await?;
    let config = match gui_config_state.update_network_endpoint(&next) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(&next, patch(&previous), || {
                patch_core_network_endpoint_settings(&previous)
            })
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    if config.host != previous.host || config.port != previous.port {
        if let Err(error) = cache.clear() {
            eprintln!("Failed to clear agent configuration status cache: {error}");
        }
    }
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn save_retry_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    settings: GuiRetrySettings,
) -> Result<CoreConfigView, String> {
    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.disable_cooling = settings.disable_cooling;
    next.request_retry = settings.request_retry;
    next.max_retry_credentials = settings.max_retry_credentials;
    next.max_retry_interval = settings.max_retry_interval;
    next.streaming_bootstrap_retries = settings.streaming_bootstrap_retries;
    let patch = |config: &GuiConfigFile| {
        serde_json::json!({
            "requests": {"streaming": {"bootstrap-retries": config.streaming_bootstrap_retries}},
            "routing": {
                "cooldown": {"disable-cooling": config.disable_cooling},
                "retry": {
                    "request-retry": config.request_retry,
                    "max-retry-credentials": config.max_retry_credentials,
                    "max-retry-interval": config.max_retry_interval
                }
            }
        })
    };
    update_core_config(&previous, patch(&next), || patch_core_retry_settings(&next)).await?;
    let config = match gui_config_state.update_retry_settings(&next) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(&next, patch(&previous), || {
                patch_core_retry_settings(&previous)
            })
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn save_session_routing_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    settings: GuiSessionRoutingSettings,
) -> Result<CoreConfigView, String> {
    let ttl = normalize_session_affinity_ttl(settings.routing_session_affinity_ttl)?;
    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.routing_session_affinity = settings.routing_session_affinity;
    next.routing_session_affinity_ttl = ttl;
    let patch = |config: &GuiConfigFile| {
        serde_json::json!({"routing": {
            "session-affinity": config.routing_session_affinity,
            "session-affinity-ttl": config.routing_session_affinity_ttl
        }})
    };
    update_core_config(&previous, patch(&next), || {
        patch_core_session_routing_settings(&next)
    })
    .await?;
    let config = match gui_config_state.update_session_routing(&next) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(&next, patch(&previous), || {
                patch_core_session_routing_settings(&previous)
            })
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn get_core_config_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreConfigView, String> {
    let settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    let api_keys = gui_api_key_values(&config.api_keys);
    if api_keys != settings.api_keys {
        update_core_config(
            &config,
            serde_json::json!({"access": {"api-keys": api_keys}}),
            || patch_core_api_keys(&api_keys),
        )
        .await?;
    }
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn save_core_logging_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    settings: CoreLoggingSettingsInput,
) -> Result<CoreConfigView, String> {
    if !(1..=3600).contains(&settings.redis_usage_queue_retention_seconds) {
        return Err("Redis usage queue retention must be between 1 and 3600 seconds".to_string());
    }

    let previous = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    let mut next = previous.clone();
    next.debug = settings.debug;
    next.commercial_mode = settings.commercial_mode;
    next.logging_to_file = settings.logging_to_file;
    next.logs_max_total_size_mb = settings.logs_max_total_size_mb;
    next.error_logs_max_files = settings.error_logs_max_files;
    next.usage_statistics_enabled = settings.usage_statistics_enabled;
    next.redis_usage_queue_retention_seconds = settings.redis_usage_queue_retention_seconds;

    let patch = |settings: &CoreConfigSettings| {
        serde_json::json!({
            "server": {"commercial-mode": settings.commercial_mode},
            "observability": {
                "logs": {
                    "debug": settings.debug,
                    "logging-to-file": settings.logging_to_file,
                    "logs-max-total-size-mb": settings.logs_max_total_size_mb,
                    "error-logs-max-files": settings.error_logs_max_files
                },
                "usage": {
                    "usage-statistics-enabled": settings.usage_statistics_enabled,
                    "redis-usage-queue-retention-seconds": settings.redis_usage_queue_retention_seconds
                }
            }
        })
    };
    let current_config = gui_config_state.snapshot()?;
    update_core_config(&current_config, patch(&next), || {
        patch_core_logging_settings(&next)
    })
    .await?;
    let config = match gui_config_state.sync_core_settings(&next) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(&current_config, patch(&previous), || {
                patch_core_logging_settings(&previous)
            })
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn add_core_api_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    api_key: String,
    remark: String,
) -> Result<CoreConfigView, String> {
    let api_key = api_key.trim().to_string();
    let remark = remark.trim().to_string();
    validate_core_api_key(&api_key)?;
    validate_api_key_remark(&remark)?;
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    if settings
        .api_keys
        .iter()
        .any(|existing| existing == &api_key)
    {
        return Err("This authentication key already exists".to_string());
    }
    settings.api_keys.push(api_key);
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"access": {"api-keys": settings.api_keys}}),
        || patch_core_api_keys(&settings.api_keys),
    )
    .await?;
    let added_api_key = settings.api_keys.last().map(|key| GuiApiKeyEntry {
        key: key.clone(),
        remark,
    });
    let config = gui_config_state.sync_core_settings_with_api_key(&settings, added_api_key)?;
    Ok(CoreConfigView::from(&config))
}

pub(crate) fn replace_core_api_key_value(
    api_keys: &mut [String],
    original_api_key: &str,
    replacement_api_key: String,
) -> Result<(), String> {
    let index = api_keys
        .iter()
        .position(|existing| existing == original_api_key)
        .ok_or_else(|| {
            "The authentication key to edit does not exist. Refresh and try again".to_string()
        })?;
    if replacement_api_key != original_api_key
        && api_keys
            .iter()
            .any(|existing| existing == &replacement_api_key)
    {
        return Err("This authentication key already exists".to_string());
    }
    api_keys[index] = replacement_api_key;
    Ok(())
}

pub(crate) fn remove_core_api_key_value(
    api_keys: &mut Vec<String>,
    api_key: &str,
) -> Result<(), String> {
    let index = api_keys
        .iter()
        .position(|existing| existing == api_key)
        .ok_or_else(|| {
            "The authentication key to delete does not exist. Refresh and try again".to_string()
        })?;
    api_keys.remove(index);
    Ok(())
}

#[tauri::command]
pub(crate) async fn update_core_api_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    original_api_key: String,
    api_key: String,
    remark: String,
) -> Result<CoreConfigView, String> {
    let original_api_key = original_api_key.trim();
    let api_key = api_key.trim().to_string();
    let remark = remark.trim().to_string();
    if original_api_key.is_empty() {
        return Err("The authentication key to edit cannot be empty".to_string());
    }
    validate_core_api_key(&api_key)?;
    validate_api_key_remark(&remark)?;

    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    replace_core_api_key_value(&mut settings.api_keys, original_api_key, api_key.clone())?;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"access": {"api-keys": settings.api_keys}}),
        || patch_core_api_keys(&settings.api_keys),
    )
    .await?;
    let config = gui_config_state.sync_core_settings_with_api_key(
        &settings,
        Some(GuiApiKeyEntry {
            key: api_key,
            remark,
        }),
    )?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn delete_core_api_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    api_key: String,
) -> Result<CoreConfigView, String> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err("The authentication key to delete cannot be empty".to_string());
    }
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    remove_core_api_key_value(&mut settings.api_keys, api_key)?;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"access": {"api-keys": settings.api_keys}}),
        || patch_core_api_keys(&settings.api_keys),
    )
    .await?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_management_secret_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    secret_key: String,
) -> Result<CoreConfigView, String> {
    let secret_key = normalize_management_secret_key(secret_key)?;
    let previous = gui_config_state.snapshot()?;
    update_core_config(
        &previous,
        serde_json::json!({"management": {"secret-key": secret_key}}),
        || patch_core_management_secret_key(&secret_key),
    )
    .await?;
    let mut next = previous.clone();
    next.management_secret_key = secret_key.clone();
    let config = match gui_config_state.set_management_secret_key(secret_key) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(
                &next,
                serde_json::json!({"management": {"secret-key": previous.management_secret_key}}),
                || patch_core_management_secret_key(&previous.management_secret_key),
            )
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn clear_core_management_secret_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreConfigView, String> {
    let previous = gui_config_state.snapshot()?;
    update_core_config(
        &previous,
        serde_json::json!({"management": {"secret-key": ""}}),
        || patch_core_management_secret_key(""),
    )
    .await?;
    let config = match gui_config_state.set_management_secret_key(String::new()) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error =
                patch_core_management_secret_key(&previous.management_secret_key).err();
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_plugins_enabled(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    enabled: bool,
) -> Result<CoreConfigView, String> {
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    settings.plugins_enabled = enabled;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"plugins": {"enabled": settings.plugins_enabled}}),
        || patch_core_plugins_enabled(settings.plugins_enabled),
    )
    .await?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_request_log(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    enabled: bool,
) -> Result<CoreConfigView, String> {
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    let previous_enabled = settings.request_log;
    settings.request_log = enabled;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"observability": {"logs": {"request-log": settings.request_log}}}),
        || patch_core_request_log(settings.request_log),
    )
    .await?;
    let config = match gui_config_state.sync_core_settings(&settings) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(
                &config,
                serde_json::json!({"observability": {"logs": {"request-log": previous_enabled}}}),
                || patch_core_request_log(previous_enabled),
            )
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_routing_strategy(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    strategy: String,
) -> Result<CoreConfigView, String> {
    validate_routing_strategy(&strategy)?;
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    settings.routing_strategy = strategy;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"routing": {"strategy": settings.routing_strategy}}),
        || patch_core_routing_strategy(&settings.routing_strategy),
    )
    .await?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_proxy_url(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    proxy_url: String,
) -> Result<CoreConfigView, String> {
    network_proxy::set_manual_via_api(gui_config_state.inner(), proxy_url).await?;
    Ok(CoreConfigView::from(&gui_config_state.snapshot()?))
}

#[tauri::command]
pub(crate) async fn set_core_session_affinity(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    enabled: bool,
) -> Result<CoreConfigView, String> {
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    let previous_enabled = settings.routing_session_affinity;
    settings.routing_session_affinity = enabled;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"routing": {"session-affinity": settings.routing_session_affinity}}),
        || patch_core_session_affinity(settings.routing_session_affinity),
    )
    .await?;
    let config = match gui_config_state.sync_core_settings(&settings) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(
                &config,
                serde_json::json!({"routing": {"session-affinity": previous_enabled}}),
                || patch_core_session_affinity(previous_enabled),
            )
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
pub(crate) async fn set_core_session_affinity_ttl(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    ttl: String,
) -> Result<CoreConfigView, String> {
    let ttl = normalize_session_affinity_ttl(ttl)?;
    let mut settings = current_core_config_settings_via_api(gui_config_state.inner()).await?;
    let previous_ttl = settings.routing_session_affinity_ttl.clone();
    settings.routing_session_affinity_ttl = ttl;
    let config = gui_config_state.snapshot()?;
    update_core_config(
        &config,
        serde_json::json!({"routing": {"session-affinity-ttl": settings.routing_session_affinity_ttl}}),
        || patch_core_session_affinity_ttl(&settings.routing_session_affinity_ttl),
    )
    .await?;
    let config = match gui_config_state.sync_core_settings(&settings) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = rollback_core_config(
                &config,
                serde_json::json!({"routing": {"session-affinity-ttl": previous_ttl}}),
                || patch_core_session_affinity_ttl(&previous_ttl),
            )
            .await;
            return Err(config_update_error_with_rollback(error, rollback_error));
        }
    };
    Ok(CoreConfigView::from(&config))
}
