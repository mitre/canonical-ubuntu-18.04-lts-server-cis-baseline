# encoding: UTF-8

control "C-5.2.18" do
  title "Ensure SSH access is limited"
  desc  "There are several options available to limit which users and group can
access the system via SSH. It is recommended that at least one of the following
options be leveraged:

    `AllowUsers`

    The `AllowUsers` variable gives the system administrator the option of
allowing specific users to `ssh` into the system. The list consists of space
separated user names. Numeric user IDs are not recognized with this variable.
If a system administrator wants to restrict user access further by only
allowing the allowed users to log in from a particular host, the entry can be
specified in the form of user@host.

    `AllowGroups`

    The `AllowGroups` variable gives the system administrator the option of
allowing specific groups of users to `ssh` into the system. The list consists
of space separated group names. Numeric group IDs are not recognized with this
variable.

    `DenyUsers`

    The `DenyUsers` variable gives the system administrator the option of
denying specific users to `ssh` into the system. The list consists of space
separated user names. Numeric user IDs are not recognized with this variable.
If a system administrator wants to restrict user access further by specifically
denying a user's access from a particular host, the entry can be specified in
the form of user@host.

    `DenyGroups`

    The `DenyGroups` variable gives the system administrator the option of
denying specific groups of users to `ssh` into the system. The list consists of
space separated group names. Numeric group IDs are not recognized with this
variable.
  "
  desc  "rationale", "Restricting which users can remotely access the system
via SSH will help ensure that only authorized users access the system."
  desc  "check", "
    Run the following commands and verify that output matches for at least one:

    ```
    # sshd -T | grep allowusers

    AllowUsers
    ```

    ```
    # sshd -T | grep allowgroups

    AllowGroups
    ```

    ```
    # sshd -T | grep denyusers

    DenyUsers
    ```

    ```
    # sshd -T | grep denygroups

    DenyGroups
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set one or more of the parameter as
follows:

    ```
    AllowUsers
    ```

    ```
    AllowGroups
    ```

    ```
    DenyUsers
    ```

    ```
    DenyGroups
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
  tag nist: ["AC-6 (9)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.3", "Rev_7"]
  tag cis_rid: "5.2.18"

  describe.one do
    describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s+(.*?)\s*$/ } ) do
      its('AllowUsers') { should be }
    end
    describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s+(.*?)\s*$/ } ) do
      its('AllowGroups') { should be }
    end
    describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s+(.*?)\s*$/ } ) do
      its('DenyUsers') { should be }
    end
    describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s+(.*?)\s*$/ } ) do
      its('DenyGroups') { should be }
    end
  end
end
