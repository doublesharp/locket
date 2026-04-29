use std::error::Error;

use crate::{AutomationClientNonceRecord, AutomationClientRecord};

use super::open_initialized_store;

#[test]
fn automation_clients_store_public_metadata_and_revocation() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    let client = AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "6b86b273ff34fce1".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned(), "redact".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    };

    test_store.store.insert_automation_client(&client)?;
    let clients = test_store.store.list_automation_clients("lk_proj_test", false)?;
    assert_eq!(clients, vec![client]);
    let by_name = test_store
        .store
        .get_automation_client("lk_proj_test", "ci")?
        .ok_or("client should exist")?;
    assert_eq!(by_name.id, "lk_client_test");

    assert!(test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 300)?);
    assert!(test_store.store.list_automation_clients("lk_proj_test", false)?.is_empty());
    let revoked = test_store.store.list_automation_clients("lk_proj_test", true)?;
    assert_eq!(revoked[0].revoked_at, Some(300));
    assert!(!test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 400)?);
    Ok(())
}

#[test]
fn automation_client_nonces_are_unique_and_prunable() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    let nonce = AutomationClientNonceRecord {
        client_id: "lk_client_test".to_owned(),
        nonce: [9; 24],
        request_timestamp: 210,
        seen_at: 220,
        expires_at: 230,
    };

    test_store.store.insert_automation_client_nonce(&nonce)?;
    assert!(test_store.store.insert_automation_client_nonce(&nonce).is_err());
    assert_eq!(test_store.store.prune_automation_client_nonces(229)?, 0);
    assert_eq!(test_store.store.prune_automation_client_nonces(230)?, 1);
    Ok(())
}
