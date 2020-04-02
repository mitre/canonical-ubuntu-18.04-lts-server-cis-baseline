# encoding: UTF-8

control "C-5.3.3" do
  title "Ensure password reuse is limited"
  desc  "The `/etc/security/opasswd` file stores the users' old passwords and
can be checked to ensure that users are not recycling recent passwords."
  desc  "rationale", "
    Forcing users not to reuse their past 5 passwords make it less likely that
an attacker will be able to guess the password.

    Note that these change only apply to accounts configured on the local
system.
  "
  desc  "check", "
    Run the following commands and ensure the `remember` option is '`5`' or
more and included in all results:

    ```
    # grep -E '^password\\s+required\\s+pam_pwhistory.so'
/etc/pam.d/common-password

    password required pam_pwhistory.so remember=5
    ```
  "
  desc "fix", "
    Edit the `/etc/pam.d/common-password` file to include the `remember` option
and conform to site policy as shown:

    ```
    password required pam_pwhistory.so remember=5
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16", "Rev_7"]
  tag cis_rid: "5.3.3"
end
