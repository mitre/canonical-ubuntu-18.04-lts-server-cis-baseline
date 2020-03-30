# encoding: UTF-8

control "C-1.7.1.3" do
  title "Ensure all AppArmor Profiles are in enforce or complain mode"
  desc  "AppArmor profiles define what resources applications are able to
access."
  desc  "rationale", "Security configuration requirements vary from site to
site. Some sites may mandate a policy that is stricter than the default policy,
which is perfectly acceptable. This item is intended to ensure that any
policies that exist on the system are activated."
  desc  "check", "
    Run the following command and verify that profiles are loaded, profiles are
in enforce or complain mode, and no processes are unconfined:

    ```
    # apparmor_status | grep profiles
    ```

    Review output and ensure that profiles are loaded, and in either enforce or
complain mode

    ```
    37 profiles are loaded.
    35 profiles are in enforce mode.
    2 profiles are in complain mode.
    4 processes have profiles defined.
    ```

    ```
    # apparmor_status | grep processes
    ```

    Review the output and ensure no processes are unconfined

    ```
    4 processes have profiles defined.
    4 processes are in enforce mode.
    0 processes are in complain mode.
    0 processes are unconfined but have a profile defined.
    ```
  "
  desc  "fix", "
    Run the following command to set all profiles to enforce mode:

    ```
    # aa-enforce /etc/apparmor.d/*
    ```

    **OR**

    Run the following command to set all profiles to complain mode:

    ```
    # aa-complain /etc/apparmor.d/*
    ```

    Any unconfined processes may need to have a profile created or activated
for them and then be restarted.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "1.7.1.3"
end
