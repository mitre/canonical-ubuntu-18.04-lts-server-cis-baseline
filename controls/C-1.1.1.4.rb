# encoding: UTF-8

control "C-1.1.1.4" do
  title "Ensure mounting of hfs filesystems is disabled"
  desc  "The `hfs` filesystem type is a hierarchical filesystem that allows you
to mount Mac OS filesystems."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the system. If this filesystem type is not needed,
disable it."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v hfs

    install /bin/true
    ```

    ```
    # lsmod | grep hfs

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/hfs.conf`

    and add the following line:

    ```
    install hfs /bin/true
    ```

    Run the following command to unload the `hfs` module:

    ```
    # rmmod hfs
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
  tag cis_rid: "1.1.1.4"

  describe kernel_module('hfs') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end

end
