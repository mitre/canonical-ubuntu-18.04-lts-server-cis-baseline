# encoding: UTF-8

control "C-5.5" do
  title "Ensure root login is restricted to system console"
  desc  "The file `/etc/securetty` contains a list of valid terminals that may
be logged in directly as root."
  desc  "rationale", "Since the system console has special properties to handle
emergency situations, it is important to ensure that the console is in a
physically secure location and that unauthorized consoles have not been
defined."
  desc  "check", "
    ```
    # cat /etc/securetty
    ```
  "
  desc "fix", "Remove entries for any consoles that are not in a physically
secure location."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-6 (9)"]
  tag cis_level: 1
  tag cis_controls: ["4.3"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.5"

  path = '/etc/securetty'
  describe file(path) do
    skip("This control must be reviewed manually. Inspect the contents of #{path}.")
  end
end
