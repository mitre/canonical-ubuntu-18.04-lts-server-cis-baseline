# encoding: UTF-8

control "C-5.3.2" do
  title "Ensure lockout for failed password attempts is configured"
  desc  "Lock out users after _n_ unsuccessful consecutive login attempts. The
first sets of changes are made to the PAM configuration files. The second set
of changes are applied to the program specific PAM configuration file. The
second set of changes must be applied to each program that will lock out users.
Check the documentation for each secondary program for instructions on how to
configure them to work with PAM.

    - deny=`n` - `n` represents the number of failed attempts before the
account is locked
    - unlock_time=`n` - `n` represents the number of seconds before the account
is unlocked
    - audit - Will log the user name into the system log if the user is not
found.
    - silent - Don't print informative messages.

    Set the lockout number and unlock time in accordance with local site policy.
  "
  desc  "rationale", "Locking out user IDs after `n` unsuccessful consecutive
login attempts mitigates brute force password attacks against your systems."
  desc  "check", "
    Verify password lockouts are configured. These settings are commonly
configured with the `pam_tally2.so` modules found in `/etc/pam.d/common-auth`.

    ```
    # grep \"pam_tally2\" /etc/pam.d/common-auth

    auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
    ```

    Verify the pam_deny.so module and pam_tally2.so modules are included in
`/etc/pam.d/common-account`

    ```
    # grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account

    account requisite pam_deny.so
    account required pam_tally2.so
    ```
  "
  desc "fix", "
    Edit the `/etc/pam.d/common-auth` file and add the auth line below:

    ```
    auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
    ```

    Edit the `/etc/pam.d/common-account` file and add the account lines bellow:

    ```
    account requisite pam_deny.so
    account required pam_tally.so
    ```

    **Note:** If a user has been locked out because they have reached the
maximum consecutive failure count defined by `deny=` in the `pam_tally2.so`
module, the user can be unlocked by issuing the command `/sbin/pam_tally2 -u
--reset`. This command sets the failed count to 0, effectively unlocking the
user.
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
  tag cis_controls: ["16.7", "Rev_7"]
  tag cis_rid: "5.3.2"
end
