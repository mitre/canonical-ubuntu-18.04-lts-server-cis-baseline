# encoding: UTF-8

control "C-1.1.1.5" do
  title "Ensure mounting of hfsplus filesystems is disabled"
  desc  "The `hfsplus` filesystem type is a hierarchical filesystem designed to
replace `hfs` that allows you to mount Mac OS filesystems."
  desc  "rationale", "Removing support for unneeded filesystem types reduces
the local attack surface of the system. If this filesystem type is not needed,
disable it."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v hfsplus

    install /bin/true
    ```

    ```
    # lsmod | grep hfsplus

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/hfsplus.conf`

    and add the following line:

    ```
    install hfsplus /bin/true
    ```

    Run the following command to unload the `hfsplus` module:

    ```
    # rmmod hfsplus
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
  tag cis_rid: "1.1.1.5"
end