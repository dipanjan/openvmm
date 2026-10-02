// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-specific configurable syscall denials.

/// Whether denying a syscall is required or workload-dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// The syscall must remain denied.
    Mandatory,
    /// The syscall may be allowed when profiling demonstrates a workload need.
    Optional,
}

/// One configured syscall denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeniedSyscall {
    /// Platform syscall name.
    pub name: &'static str,
    /// Whether the denial is mandatory or optional.
    pub enforcement: Enforcement,
    /// Security rationale for denying the syscall.
    pub reason: Option<&'static str>,
}

/// Iterate over the syscall denials configured for the current platform.
pub fn platform_syscall_denylist() -> impl Iterator<Item = &'static DeniedSyscall> {
    #[cfg(target_os = "linux")]
    {
        crate::unix::syscall_denylist::SYSCALL_DENYLIST_MANDATORY
            .iter()
            .chain(crate::unix::syscall_denylist::SYSCALL_DENYLIST_OPTIONAL)
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::iter::empty()
    }
}
