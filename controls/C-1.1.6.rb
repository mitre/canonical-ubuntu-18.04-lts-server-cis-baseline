# encoding: UTF-8

control "C-1.1.6" do
  title "Ensure separate partition exists for /var"
  desc  "The `/var` directory is used by daemons and other system services to
temporarily store dynamic data. Some directories created by these processes may
be world-writable."
  desc  "rationale", "Since the `/var` directory may contain world-writable
files and directories, there is a risk of resource exhaustion if it is not
bound to a separate partition."
  desc  "check", "
    Run the following command and verify output shows `/var` is mounted:

    ```
    # mount | grep -E '\\s/var\\s'
    /dev/xvdg1 on /var type ext4 (rw,relatime,data=ordered)
    ```
  "
  desc  "fix", "
    For new installations, during installation create a custom partition setup
and specify a separate partition for `/var` .

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
  tag cis_rid: "1.1.6"

  describe mount('/var') do
    it { should be_mounted }
  end

end
