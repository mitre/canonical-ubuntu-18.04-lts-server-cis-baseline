# encoding: UTF-8

control "C-6.1.4" do
  title "Ensure permissions on /etc/shadow are configured"
  desc  "The `/etc/shadow` file is used to store the information about user
accounts that is critical to the security of those accounts, such as the hashed
password and other security information."
  desc  "rationale", "If attackers can gain read access to the `/etc/shadow`
file, they can easily run a password cracking program against the hashed
password to break it. Other security information that is stored in the
`/etc/shadow` file (such as expiration) could also be useful to subvert the
user accounts."
  desc  "check", "
    Run the following command and verify verify `Uid` is `0/root,` `Gid` is
`/shadow,` and `Access` is `640` or more restrictive:

    ```
    # stat /etc/shadow

    Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 42/ shadow)
    ```
  "
  desc  "fix", "
    Run the one following commands to set permissions on `/etc/shadow`:

    ```
    # chmod o-rwx,g-wx /etc/shadow
    ```

    ```
    # chown root:shadow /etc/shadow
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
  tag nist: ["SC-28", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.4", "Rev_7"]
  tag cis_rid: "6.1.4"
end
