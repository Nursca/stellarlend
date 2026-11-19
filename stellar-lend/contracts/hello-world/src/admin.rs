use soroban_sdk::{contracttype, Address, Env, Symbol, Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
    Unauthorized,
    InvalidAdmin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub struct AdminRotationProposal {
    pub new_admin: Address,
    pub approvals: Vec<Address>,
}

pub fn require_admin(env: &Env, caller: &Address) -> Result<(), AdminError> {
    let current_admin = get_admin(env).ok_or(AdminError::Unauthorized)?;
    caller.require_auth();
    if *caller != current_admin {
        return Err(AdminError::Unauthorized);
    }
    Ok(())
}

pub fn set_admin(env: &Env, new_admin: Address, caller: Option<Address>) -> Result<(), AdminError> {
    if let Some(current_admin) = get_admin(env) {
        if let Some(ref c) = caller {
            // Caller must be the current admin AND provide cryptographic auth
            c.require_auth();
            if *c != current_admin {
                return Err(AdminError::Unauthorized);
            }
        } else {
            return Err(AdminError::Unauthorized);
        }

        if let Some((_, threshold)) = get_security_council(env) {
            if threshold > 0 {
                let proposal = env
                    .storage()
                    .persistent()
                    .get::<_, AdminRotationProposal>(&AdminDataKey::AdminRotationProposal(
                        new_admin.clone(),
                    ))
                    .ok_or(AdminError::Unauthorized)?;
                if proposal.approvals.len() < threshold as u32 {
                    return Err(AdminError::Unauthorized);
                }
            }
        }
    }

    env.storage()
        .persistent()
        .set(&AdminDataKey::Admin, &new_admin);
    Ok(())
}

#[contracttype]
#[derive(Clone)]
pub enum AdminDataKey {
    Admin,
    SecurityCouncil,
    SecurityCouncilThreshold,
    AdminRotationProposal(Address),
}

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage()
        .persistent()
        .get::<_, Address>(&AdminDataKey::Admin)
}

pub fn set_security_council(
    env: &Env,
    caller: Address,
    council: Vec<Address>,
    threshold: u32,
) -> Result<(), AdminError> {
    require_admin(env, &caller)?;
    if council.is_empty() || threshold == 0 || threshold > council.len() as u32 {
        return Err(AdminError::InvalidAdmin);
    }
    for (i, member) in council.iter().enumerate() {
        if council.iter().skip(i + 1).any(|other| other == member) {
            return Err(AdminError::InvalidAdmin);
        }
    }
    env.storage()
        .persistent()
        .set(&AdminDataKey::SecurityCouncil, &council);
    env.storage()
        .persistent()
        .set(&AdminDataKey::SecurityCouncilThreshold, &threshold);
    Ok(())
}

pub fn get_security_council(env: &Env) -> Option<(Vec<Address>, u32)> {
    let council = env
        .storage()
        .persistent()
        .get::<_, Vec<Address>>(&AdminDataKey::SecurityCouncil)?;
    let threshold = env
        .storage()
        .persistent()
        .get::<_, u32>(&AdminDataKey::SecurityCouncilThreshold)
        .unwrap_or(1);
    Some((council, threshold))
}

pub fn propose_admin_rotation(
    env: &Env,
    proposer: Address,
    new_admin: Address,
) -> Result<(), AdminError> {
    proposer.require_auth();
    let (council, _) = get_security_council(env).ok_or(AdminError::Unauthorized)?;
    if !council.contains(&proposer) {
        return Err(AdminError::Unauthorized);
    }
    if new_admin == env.current_contract_address() {
        return Err(AdminError::InvalidAdmin);
    }

    let proposal = AdminRotationProposal {
        new_admin: new_admin.clone(),
        approvals: Vec::from_array(env, [proposer]),
    };
    env.storage()
        .persistent()
        .set(&AdminDataKey::AdminRotationProposal(new_admin), &proposal);
    Ok(())
}

pub fn approve_admin_rotation(
    env: &Env,
    approver: Address,
    new_admin: Address,
) -> Result<(), AdminError> {
    approver.require_auth();
    let (council, _) = get_security_council(env).ok_or(AdminError::Unauthorized)?;
    if !council.contains(&approver) {
        return Err(AdminError::Unauthorized);
    }

    let mut proposal = env
        .storage()
        .persistent()
        .get::<_, AdminRotationProposal>(&AdminDataKey::AdminRotationProposal(new_admin.clone()))
        .ok_or(AdminError::Unauthorized)?;
    if proposal.approvals.contains(&approver) {
        return Err(AdminError::Unauthorized);
    }
    proposal.approvals.push_back(approver);
    env.storage()
        .persistent()
        .set(&AdminDataKey::AdminRotationProposal(new_admin), &proposal);
    Ok(())
}

pub fn execute_admin_rotation(
    env: &Env,
    executor: Address,
    new_admin: Address,
) -> Result<(), AdminError> {
    executor.require_auth();
    let (council, threshold) = get_security_council(env).ok_or(AdminError::Unauthorized)?;
    if !council.contains(&executor) {
        return Err(AdminError::Unauthorized);
    }
    let proposal = env
        .storage()
        .persistent()
        .get::<_, AdminRotationProposal>(&AdminDataKey::AdminRotationProposal(new_admin.clone()))
        .ok_or(AdminError::Unauthorized)?;
    if proposal.approvals.len() < threshold as u32 {
        return Err(AdminError::Unauthorized);
    }
    env.storage()
        .persistent()
        .set(&AdminDataKey::Admin, &new_admin);
    env.storage()
        .persistent()
        .remove(&AdminDataKey::AdminRotationProposal(new_admin));
    Ok(())
}

/// Returns whether `caller` holds `role`. The protocol admin implicitly
/// holds every role; additional role grants are not persisted yet.
pub fn has_role(env: &Env, _role: Symbol, caller: Address) -> bool {
    get_admin(env).map(|a| a == caller).unwrap_or(false)
}
