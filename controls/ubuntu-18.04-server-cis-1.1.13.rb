# encoding: UTF-8

control "C-1.1.13" do
  title "Ensure separate partition exists for /home"
  desc  "The `/home` directory is used to support disk storage needs of local
users."
  desc  "rationale", "If the system is intended to support local users, create
a separate partition for the `/home` directory to protect against resource
exhaustion and restrict the type of files that can be stored under `/home` ."
  desc  "check", "
    Run the following command and verify output shows `/home` is mounted:
    ```
    # mount | grep /home
    /dev/xvdf1 on /home type ext4 (rw,nodev,relatime,data=ordered)
    ```
  "
  desc  "fix", "
    For new installations, during installation create a custom partition setup
and specify a separate partition for `/home` .

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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "1.1.13"

  describe mount('/home') do
    it { should be_mounted }
  end

end
