# encoding: UTF-8

control "C-1.1.1.1" do
  title "Ensure mounting of cramfs filesystems is disabled"
  desc  "The `cramfs` filesystem type is a compressed read-only Linux
filesystem embedded in small footprint systems. A `cramfs` image can be used
without having to first decompress the image."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the server. If this filesystem type is not needed,
disable it."
  desc  "check", "
    Run the following commands and verify the output is as indicated:
    ```
    # modprobe -n -v cramfs | grep -v mtd

    install /bin/true
    ```

    ```
    # lsmod | grep cramfs

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/cramfs.conf`

    and add the following line:

    ```
    install cramfs /bin/true
    ```

    Run the following command to unload the `cramfs` module:

    ```
    # rmmod cramfs
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
  tag cis_rid: "1.1.1.1"

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end

end
