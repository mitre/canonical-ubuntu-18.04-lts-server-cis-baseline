# encoding: UTF-8

control "C-1.3.1" do
  title "Ensure sudo is installed"
  desc  "sudo allows a permitted user to execute a command as the superuser or
another user, as specified by the security policy. The invoking user's real
(not effective) user ID is used to determine the user name with which to query
the security policy."
  desc  "rationale", "
    sudo supports a plugin architecture for security policies and input/output
logging. Third parties can develop and distribute their own policy and I/O
logging plugins to work seamlessly with the sudo front end. The default
security policy is sudoers, which is configured via the file /etc/sudoers.

    The security policy determines what privileges, if any, a user has to run
sudo. The policy may require that users authenticate themselves with a password
or another authentication mechanism. If authentication is required, sudo will
exit if the user's password is not entered within a configurable time limit.
This limit is policy-specific.
  "
  desc "check", "
    Verify that sudo in installed.

    Run the following command and inspect the output to confirm that sudo is
installed:

    ```
    # dpkg -s sudo
    ```

    OR

    ```
    # dpkg -s sudo-ldap
    ```
  "
  desc "fix", "
    Install sudo using the following command.

    ```
    # apt install sudo
    ```

    OR

    ```
    # apt install sudo-ldap
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
  tag cis_rid: "1.3.1"

  describe package('sudo') do
    it { should be_installed }
  end

  describe package('sudo-ldap') do
    it { should be_installed }
  end

end
