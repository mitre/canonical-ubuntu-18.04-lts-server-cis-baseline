# encoding: UTF-8

control "C-1.1.7" do
  title "Ensure separate partition exists for /var/tmp"
  desc  "The `/var/tmp` directory is a world-writable directory used for
temporary storage by all users and some applications."
  desc  "rationale", "Since the `/var/tmp` directory is intended to be
world-writable, there is a risk of resource exhaustion if it is not bound to a
separate partition. In addition, making `/var/tmp` its own file system allows
an administrator to set the `noexec` option on the mount, making `/var/tmp`
useless for an attacker to install executable code. It would also prevent an
attacker from establishing a hardlink to a system `setuid` program and wait for
it to be updated. Once the program was updated, the hardlink would be broken
and the attacker would have his own copy of the program. If the program
happened to have a security vulnerability, the attacker could continue to
exploit the known flaw."
  desc  "check", "
    Run the following command and verify output shows `/var/tmp` is mounted:
    ```
    # mount | grep /var/tmp
     on /var/tmp type ext4 (rw,nosuid,nodev,noexec,relatime)
    ```
  "
  desc  "fix", "
    For new installations, during installation create a custom partition setup
and specify a separate partition for `/var/tmp` .

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
  tag cis_rid: "1.1.7"

  describe mount('/var/tmp') do
    it { should be_mounted }
  end

end
