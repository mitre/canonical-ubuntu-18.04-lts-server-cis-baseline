# encoding: UTF-8

control "C-5.6" do
  title "Ensure access to the su command is restricted"
  desc  "The `su` command allows a user to run a command or shell as another
user. The program has been superseded by `sudo` , which allows for more
granular control over privileged access. Normally, the `su` command can be
executed by any user. By uncommenting the `pam_wheel.so` statement in
`/etc/pam.d/su` , the `su` command will only allow users in a specific groups
to execute `su`. This group should be empty to reinforce the use of `sudo` for
privileged access."
  desc  "rationale", "Restricting the use of `su` , and using `sudo` in its
place, provides system administrators better control of the escalation of user
privileges to execute privileged commands. The sudo utility also provides a
better logging and audit mechanism, as it can log each command executed via
`sudo` , whereas `su` can only record that a user executed the `su` program."
  desc  "check", "
    Run the following command and verify the output matches the line:

    ```
    # grep pam_wheel.so /etc/pam.d/su

    auth required pam_wheel.so use_uid group=
    ```

    Run the following command and verify that the group specified in ``
contains no users:

    ```
    # grep  /etc/group

    :x::
    ```

    There should be no users listed after the Group ID field.
  "
  desc "fix", "
    Create an empty group that will be specified for use of the `su` command.
The group should be named according to site policy.

    ```
    groupadd sugroup
    ```

    Add the following line to the `/etc/pam.d/su` file, specifying the empty
group:

    ```
    auth required pam_wheel.so use_uid group=sugroup
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.6"

  cmd = command('grep pam_wheel.so /etc/pam.d/su')
  re = /^\s*auth\s*required\s*pam_wheel.so\s*use_uid\s*group=(\w+)/
  describe cmd do
    its('stdout') { should match re }
  end
  group_match = cmd.stdout.match(re)
  if group_match
    describe group(group_match[1]) do
      its('members') { should be_empty }
    end
  end
end
