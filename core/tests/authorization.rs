use epidermis_core::{
    Action, Challenge, Claim, Credential, CredentialBody, InMemoryReplayStore,
    InMemoryTrustRegistry, KeyPair, Policy, Presentation, Verifier, VerifyError,
};

fn payment() -> Action {
    Action::new(
        "bank.transfer".into(),
        vec![
            ("amount_minor".into(), "2500000000".into()),
            ("currency".into(), "USD".into()),
            ("destination_account".into(), "US123456789".into()),
            ("source_account".into(), "US987654321".into()),
        ],
    )
    .unwrap()
}

fn role() -> Claim {
    Claim {
        kind: "role".into(),
        value: "treasury_approver".into(),
    }
}

fn credential(issuer: &KeyPair, holder: &KeyPair, subject_id: [u8; 32]) -> Credential {
    Credential::issue(
        CredentialBody::new(
            "employer".into(),
            subject_id,
            holder.public_key(),
            vec![role()],
            100,
            1000,
        )
        .unwrap(),
        issuer,
    )
    .unwrap()
}

#[test]
fn two_people_approve_exact_action_only_once() {
    let issuer = KeyPair::generate().unwrap();
    let alice = KeyPair::generate().unwrap();
    let bob = KeyPair::generate().unwrap();
    let mut registry = InMemoryTrustRegistry::default();
    registry.add_issuer("employer".into(), issuer.public_key(), ["role".into()]);
    let replay = InMemoryReplayStore::default();
    let action = payment();
    let challenge = Challenge::new("bank.example".into(), &action, 200, 260).unwrap();
    assert!(replay.register(&challenge));
    let approvals = [
        Presentation::sign(credential(&issuer, &alice, [1; 32]), &challenge, &alice).unwrap(),
        Presentation::sign(credential(&issuer, &bob, [2; 32]), &challenge, &bob).unwrap(),
    ];
    let policy = Policy {
        required_claims: vec![role()],
        min_distinct_approvers: 2,
    };
    let verifier = Verifier {
        registry: &registry,
        replay_store: &replay,
        audience: "bank.example",
    };

    let mut altered = action.clone();
    altered.fields[0].1 = "2600000000".into();
    assert_eq!(
        verifier
            .verify(&altered, &challenge, &approvals, &policy, 220)
            .unwrap_err(),
        VerifyError::ActionMismatch
    );
    assert_eq!(
        verifier
            .verify(&action, &challenge, &approvals[..1], &policy, 220)
            .unwrap_err(),
        VerifyError::InsufficientApprovals
    );
    let bob_same_person =
        Presentation::sign(credential(&issuer, &bob, [1; 32]), &challenge, &bob).unwrap();
    assert_eq!(
        verifier
            .verify(
                &action,
                &challenge,
                &[approvals[0].clone(), bob_same_person],
                &policy,
                220
            )
            .unwrap_err(),
        VerifyError::DuplicateApprover
    );
    assert_eq!(
        verifier
            .verify(&action, &challenge, &approvals, &policy, 220)
            .unwrap()
            .approver_fingerprints
            .len(),
        2
    );
    assert_eq!(
        verifier
            .verify(&action, &challenge, &approvals, &policy, 220)
            .unwrap_err(),
        VerifyError::Replay
    );
    assert!(!replay.register(&challenge));
}

#[test]
fn revoked_and_unauthorized_credentials_fail_closed() {
    let issuer = KeyPair::generate().unwrap();
    let holder = KeyPair::generate().unwrap();
    let mut registry = InMemoryTrustRegistry::default();
    registry.add_issuer("employer".into(), issuer.public_key(), ["role".into()]);
    let replay = InMemoryReplayStore::default();
    let action = payment();
    let challenge = Challenge::new("bank.example".into(), &action, 200, 260).unwrap();
    assert!(replay.register(&challenge));
    let cred = credential(&issuer, &holder, [1; 32]);
    let presentation = Presentation::sign(cred.clone(), &challenge, &holder).unwrap();
    let policy = Policy {
        required_claims: vec![role()],
        min_distinct_approvers: 1,
    };
    registry.revoke(cred.body.id);
    let verifier = Verifier {
        registry: &registry,
        replay_store: &replay,
        audience: "bank.example",
    };
    assert_eq!(
        verifier
            .verify(&action, &challenge, &[presentation], &policy, 220)
            .unwrap_err(),
        VerifyError::RevokedCredential
    );
}

#[test]
fn tampered_credential_and_wrong_audience_fail() {
    let issuer = KeyPair::generate().unwrap();
    let holder = KeyPair::generate().unwrap();
    let mut registry = InMemoryTrustRegistry::default();
    registry.add_issuer("employer".into(), issuer.public_key(), ["role".into()]);
    let replay = InMemoryReplayStore::default();
    let action = payment();
    let challenge = Challenge::new("bank.example".into(), &action, 200, 260).unwrap();
    assert!(replay.register(&challenge));
    let mut presentation =
        Presentation::sign(credential(&issuer, &holder, [1; 32]), &challenge, &holder).unwrap();
    let policy = Policy {
        required_claims: vec![role()],
        min_distinct_approvers: 1,
    };
    let verifier = Verifier {
        registry: &registry,
        replay_store: &replay,
        audience: "other-bank.example",
    };
    assert_eq!(
        verifier
            .verify(&action, &challenge, &[presentation.clone()], &policy, 220)
            .unwrap_err(),
        VerifyError::AudienceMismatch
    );
    let verifier = Verifier {
        registry: &registry,
        replay_store: &replay,
        audience: "bank.example",
    };
    presentation.credential.body.expires_at = 999;
    assert_eq!(
        verifier
            .verify(&action, &challenge, &[presentation], &policy, 220)
            .unwrap_err(),
        VerifyError::InvalidCredential
    );
}
