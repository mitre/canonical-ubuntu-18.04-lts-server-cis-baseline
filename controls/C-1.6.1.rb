# encoding: UTF-8

control "C-1.6.1" do
  title "Ensure XD/NX support is enabled"
  desc  "Recent processors in the x86 family support the ability to prevent
code execution on a per memory page basis. Generically and on AMD processors,
this ability is called No Execute (NX), while on Intel processors it is called
Execute Disable (XD). This ability can help prevent exploitation of buffer
overflow vulnerabilities and should be activated whenever possible. Extra steps
must be taken to ensure that this protection is enabled, particularly on 32-bit
x86 systems. Other processors, such as Itanium and POWER, have included such
support since inception and the standard kernel for those platforms supports
the feature."
  desc  "rationale", "Enabling any feature that can protect against buffer
overflow attacks enhances the security of the system."
  desc  "check", "
    Run the following command and verify your kernel has identified and
activated NX/XD protection.

    ```
    # journalctl | grep 'protection: active'

    kernel: NX (Execute Disable) protection: active
    ```

    OR

    on systems without journalctl

    ```
    # [[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i '
(pae|nx) ' /proc/cpuinfo) || -n $(grep '\\sNX\\s.*\\sprotection:\\s'
/var/log/dmesg | grep -v active) ]] && echo \"NX Protection is not active\"
    ```

    Nothing should be returned
  "
  desc "fix", "
    On 32 bit systems install a kernel with PAE support, no installation is
required on 64 bit systems:

    If necessary configure your bootloader to load the new kernel and reboot
the system.

    You may need to enable NX or XD support in your bios.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SI-16", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["8.3", "Rev_7"]
  tag cis_rid: "1.6.1"

  describe command("journalctl | grep 'protection: active'").stdout.strip.split("\n") do
    its('length') { should be > 0 }
  end

end
