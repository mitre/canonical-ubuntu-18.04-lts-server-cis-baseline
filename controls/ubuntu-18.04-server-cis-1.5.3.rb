# encoding: UTF-8

control "C-1.5.3" do
  title "Ensure authentication required for single user mode"
  desc  "Single user mode is used for recovery when the system detects an issue
during boot or by manual selection from the bootloader."
  desc  "rationale", "Requiring authentication in single user mode prevents an
unauthorized user from rebooting the system into single user to gain root
privileges without credentials."
  desc  "check", "
    Perform the following to determine if a password is set for the `root` user:

    ```
    # grep ^root:[*\\!]: /etc/shadow
    ```

    No results should be returned.
  "
  desc  "fix", "
    Run the following command and follow the prompts to set a password for the
`root` user:

    ```
    # passwd root
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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "1.5.3"

  describe shadow do
    its('users') { should include 'root' }
  end

  describe shadow.where(user: 'root') do
    its('passwords') { should_not include '!' }
  end
  describe shadow.where(user: 'root') do
    its('passwords') { should_not include '*' }
  end
end

