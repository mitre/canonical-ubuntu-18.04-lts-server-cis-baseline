# encoding: UTF-8

control "C-1.1.1.3" do
  title "Ensure mounting of jffs2 filesystems is disabled"
  desc  "The `jffs2` (journaling flash filesystem 2) filesystem type is a
log-structured filesystem used in flash memory devices."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the system. If this filesystem type is not needed,
disable it."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v jffs2 | grep -v mtd

    install /bin/true
    ```

    ```
    # lsmod | grep jffs2

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/jffs2.conf`

    and add the following line:

    ```
    install jffs2 /bin/true
    ```

    Run the following command to unload the `jffs2` module:

    ```
    # rmmod jffs2
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
  tag cis_rid: "1.1.1.3"

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end

end
