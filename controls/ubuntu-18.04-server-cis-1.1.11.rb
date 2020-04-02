# encoding: UTF-8

control "C-1.1.11" do
  title "Ensure separate partition exists for /var/log"
  desc  "The `/var/log` directory is used by system services to store log data
."
  desc  "rationale", "There are two important reasons to ensure that system
logs are stored on a separate partition: protection against resource exhaustion
(since logs can grow quite large) and protection of audit data."
  desc  "check", "
    Run the following command and verify output shows `/var/log` is mounted:
    ```
    # mount | grep /var/log
    /dev/xvdh1 on /var/log type ext4 (rw,relatime,data=ordered)
    ```
  "
  desc  "fix", "
    For new installations, during installation create a custom partition setup
and specify a separate partition for `/var/log` .

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
  tag cis_rid: "1.1.11"

  describe mount('/var/log') do
    it { should be_mounted }
  end

end
