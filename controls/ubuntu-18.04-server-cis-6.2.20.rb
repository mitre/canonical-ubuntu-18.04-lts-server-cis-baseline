# encoding: UTF-8

control "C-6.2.20" do
  title "Ensure shadow group is empty"
  desc  "The shadow group allows system programs which require access the
ability to read the /etc/shadow file. No users should be assigned to the shadow
group."
  desc  "rationale", "Any users assigned to the shadow group would be granted
read access to the /etc/shadow file. If attackers can gain read access to the
`/etc/shadow` file, they can easily run a password cracking program against the
hashed passwords to break them. Other security information that is stored in
the `/etc/shadow` file (such as expiration) could also be useful to subvert
additional user accounts."
  desc  "check", "
    Run the following commands and verify no results are returned:

    ```
    # grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
    ```

    ```
    # awk -F: '($4 == \"\") { print }' /etc/passwd
    ```
  "
  desc "fix", "Remove all users from the shadow group, and change the primary
group of any users with shadow as their primary group."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.20"

  describe groups.where { name == 'shadow' } do
    it { should exist }
    its('members') { should be_empty }
  end

end
