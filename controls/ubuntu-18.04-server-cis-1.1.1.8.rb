# encoding: UTF-8

control "C-1.1.1.8" do
  title "Ensure mounting of FAT filesystems is limited"
  desc  "The `FAT` filesystem format is primarily used on older windows systems
and portable USB drives or flash modules. It comes in three types `FAT12` ,
`FAT16` , and `FAT32` all of which are supported by the `vfat` kernel module."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the system. If this filesystem type is not needed,
disable it."
  desc  "check", "
    If utilizing UEFI the `FAT` filesystem format is required. If this case,
ensure that the `FAT` filesystem is only used where appropriate

    Run the following command

    ```
    grep -E -i '\\svfat\\s' /etc/fstab
    ```

    And review that any output is appropriate for your environment

    If not utilizing UEFI

    Run the following commands and verify the output is as indicated:

    ```
    # modprobe --showconfig | grep vfat

    install vfat /bin/true
    ```

    ```
    # lsmod | grep vfat

    ```
  "
  desc "fix", "
    Edit or create a file in the /etc/modprobe.d/ directory ending in .conf

    Example: `vi /etc/modprobe.d/vfat.conf`

    ```
    install vfat /bin/true
    ```

    Run the following command to unload the `vfat` module:

    ```
    # rmmod vfat
    ```
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
  tag cis_rid: "1.1.1.8"

  describe kernel_module('vfat') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end

end
