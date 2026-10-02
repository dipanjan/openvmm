// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sandbox policy definitions for OpenVMM worker hosts.

#[derive(Copy, Clone)]
pub(crate) enum SandboxRole {
    Vm,
    Tpm,
}

impl SandboxRole {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::Tpm => "tpm",
        }
    }

    pub(crate) fn profile(self) -> sandbox::Profile {
        match self {
            Self::Vm => sandbox::profiles::minimal()
                .name(self.name())
                .read("/usr")
                .read("/etc")
                .read("/dev")
                .syscalls(sandbox::Syscalls::Deny(vec!["kill".to_string()]))
                .build(),
            Self::Tpm => sandbox::Profile::deny_all()
                .name(self.name())
                .network(sandbox::Network::None)
                .syscalls(sandbox::Syscalls::Deny(vec![
                    "kill".to_string(),
                    "tkill".to_string(),
                    "tgkill".to_string(),
                ]))
                .build(),
        }
    }
}
