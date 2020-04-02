# encoding: UTF-8

control "C-1.1.12" do
  title "Ensure separate partition exists for /var/log/audit"
  desc  "The auditing daemon, `auditd` , stores log data in the
`/var/log/audit` directory."
  desc  "rationale", "There are two important reasons to ensure that data
gathered by `auditd` is stored on a separate partition: protection against
resource exhaustion (since the `audit.log` file can grow quite large) and
protection of audit data. The audit daemon calculates how much free space is
left and performs actions based on the results. If other processes (such as
`syslog` ) consume space in the same partition as `auditd` , it may not perform
as desired."
  desc  "check", "
    Run the following command and verify output shows `/var/log/audit` is
mounted:
    ```
    # mount | grep /var/log/audit
    /dev/xvdi1 on /var/log/audit type ext4 (rw,relatime,data=ordered)
    ```
  "
  desc  "fix", "
    For new installations, during installation create a custom partition setup
and specify a separate partition for `/var/log/audit` .

    For systems that were previously installed, create a new partition and
configure `/etc/fstab` as appropriate.
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AU-4", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["6.4", "Rev_7"]
  tag cis_rid: "1.1.12"

  describe mount('/var/log/audit') do
    it { should be_mounted }
  end

end
