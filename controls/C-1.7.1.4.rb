# encoding: UTF-8

control "C-1.7.1.4" do
  title "Ensure all AppArmor Profiles are enforcing"
  desc  "AppArmor profiles define what resources applications are able to
access."
  desc  "rationale", "Security configuration requirements vary from site to
site. Some sites may mandate a policy that is stricter than the default policy,
which is perfectly acceptable. This item is intended to ensure that any
policies that exist on the system are activated."
  desc  "check", "
    Run the following command and verify that profiles are loaded, no profiles
are in complain mode, and no processes are unconfined:

    ```
    # apparmor_status
    apparmor module is loaded.
    17 profiles are loaded.
    17 profiles are in enforce mode.
     /bin/ping
     /sbin/klogd
     /sbin/syslog-ng
     /sbin/syslogd
     /usr/lib/PolicyKit/polkit-explicit-grant-helper
     /usr/lib/PolicyKit/polkit-grant-helper
     /usr/lib/PolicyKit/polkit-grant-helper-pam
     /usr/lib/PolicyKit/polkit-read-auth-helper
     /usr/lib/PolicyKit/polkit-resolve-exe-helper
     /usr/lib/PolicyKit/polkit-revoke-helper
     /usr/lib/PolicyKit/polkitd
     /usr/sbin/avahi-daemon
     /usr/sbin/identd
     /usr/sbin/mdnsd
     /usr/sbin/nscd
     /usr/sbin/ntpd
     /usr/sbin/traceroute
    0 profiles are in complain mode.
    1 processes have profiles defined.
    1 processes are in enforce mode :
     /usr/sbin/nscd (3979)
    0 processes are in complain mode.
    0 processes are unconfined but have a profile defined.
    ```
  "
  desc  "fix", "
    Run the following command to set all profiles to enforce mode:

    ```
    # aa-enforce /etc/apparmor.d/*
    ```

    Any unconfined processes may need to have a profile created or activated
for them and then be restarted.
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "1.7.1.4"
end
