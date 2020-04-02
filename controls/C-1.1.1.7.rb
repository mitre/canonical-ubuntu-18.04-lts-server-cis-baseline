# encoding: UTF-8

control "C-1.1.1.7" do
  title "Ensure mounting of udf filesystems is disabled"
  desc  "The `udf` filesystem type is the universal disk format used to
implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor
filesystem type for data storage on a broad range of media. This filesystem
type is necessary to support writing DVDs and newer optical disc formats."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the system. If this filesystem type is not needed,
disable it."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v udf | grep -v crc-itu-t

    install /bin/true
    ```

    ```
    # lsmod | grep udf

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/udf.conf`

    and add the following line:

    ```
    install udf /bin/true
    ```

    Run the following command to unload the `udf` module:

    ```
    # rmmod udf
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
  tag cis_rid: "1.1.1.7"

  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end

end
