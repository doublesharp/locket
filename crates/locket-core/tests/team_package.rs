//! Raw signature and external trust binding tests.
#![allow(unused_crate_dependencies)]
use ed25519_dalek::SigningKey;
use locket_core::team_package::{DeviceIdentity, SignedStatement, TeamMember, TeamStatement};

fn fixture() -> TeamStatement {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let device = DeviceIdentity::new("owner".into(), signer.verifying_key().to_bytes(), [8; 32]);
    TeamStatement {
        v: 1,
        team_id: "team".into(),
        project_id: "project".into(),
        epoch: 1,
        previous_digest: String::new(),
        issued_at: 100,
        expires_at: 200,
        nonce: [3; 24],
        publisher: device.clone(),
        recipient: device.clone(),
        members: vec![TeamMember {
            id: "member".into(),
            name: "owner".into(),
            role: "owner".into(),
            profiles: vec![],
            device,
            removed: false,
        }],
        profiles: vec![],
    }
}

#[test]
fn statement_signature_requires_external_pin_and_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let signed = SignedStatement::sign(&statement, &key)?;
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_ok()
    );
    assert!(signed.verify(&"a".repeat(64), "project", &statement.recipient, 150).is_err());
    let mut tampered = signed.clone();
    tampered.statement.push(b' ');
    assert!(
        tampered
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_err()
    );
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "other", &statement.recipient, 150)
            .is_err()
    );
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 501)
            .is_err()
    );
    Ok(())
}

#[test]
fn forwarded_statement_and_self_declared_non_owner_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let other = DeviceIdentity::new("other".into(), [9; 32], [10; 32]);
    let signed = SignedStatement::sign(&statement, &key)?;
    assert!(signed.verify(&statement.publisher.fingerprint, "project", &other, 150).is_err());
    statement.members[0].role = "maintainer".into();
    assert!(
        SignedStatement::sign(&statement, &key)?
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_err()
    );
    Ok(())
}

#[test]
fn established_updates_verify_after_join_expiry_without_changing_clock()
-> Result<(), Box<dyn std::error::Error>> {
    let statement = fixture();
    let signed = SignedStatement::sign(&statement, &SigningKey::from_bytes(&[7; 32]))?;
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 1000)
            .is_err()
    );
    assert!(
        signed
            .verify_update(&statement.publisher.fingerprint, "project", &statement.recipient, 1000)
            .is_ok()
    );
    assert!(
        signed
            .verify_update(&statement.publisher.fingerprint, "project", &statement.recipient, -1000)
            .is_err()
    );
    Ok(())
}
