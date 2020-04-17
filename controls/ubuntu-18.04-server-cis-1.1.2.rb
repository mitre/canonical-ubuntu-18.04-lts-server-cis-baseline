# encoding: UTF-8

control "C-1.1.2" do
  title "Ensure /tmp is configured"
  desc  "The `/tmp` directory is a world-writable directory used for temporary
storage by all users and some applications."
  desc  "rationale", "
    Making /tmp its own file system allows an administrator to set the noexec
option on the mount, making /tmp useless for an attacker to install executable
code. It would also prevent an attacker from establishing a hardlink to a
system setuid program and wait for it to be updated. Once the program was
updated, the hardlink would be broken and the attacker would have his own copy
of the program. If the program happened to have a security vulnerability, the
attacker could continue to exploit the known flaw.

    This can be accomplished by either mounting tmpfs to /tmp, or creating a
separate partition for /tmp.
  "
  desc  "check", "
    Run the following command and verify output shows `/tmp` is mounted:

    ```
    # mount | grep -E '\\s/tmp\\s'

    tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
    ```

    Run the following command and verify that tmpfs has been mounted to, or a
system partition has been created for `/tmp`

    ```
    # grep -E '\\s/tmp\\s' /etc/fstab | grep -E -v '^\\s*#'

    tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0
    ```

    OR

    ```
    # systemctl is-enabled tmp.mount

    enabled
    ```
  "
  desc "fix", "
    Configure `/etc/fstab` as appropriate.

    **Example:**

    ```
    tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
    ```

    OR

    Run the following commands to enable systemd `/tmp` mounting:

    ```
    systemctl unmask tmp.mount
    systemctl enable tmp.mount
    ```

    Edit `/etc/systemd/system/local-fs.target.wants/tmp.mount` to configure the
`/tmp` mount:

    ```
    [Mount]
    What=tmpfs
    Where=/tmp
    Type=tmpfs
    Options=mode=1777,strictatime,noexec,nodev,nosuid
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
  tag cis_rid: "1.1.2"

  describe.one do
    describe systemd_service('tmp.mount') do
      it { should be_enabled }
    end
    describe etc_fstab.where { mount_point == '/tmp' } do
      its('count') { should cmp 1 }
      it 'Should have a device name specified' do
        expect(subject.device_name[0]).to_not(be_empty)
      end
    end
  end

end
