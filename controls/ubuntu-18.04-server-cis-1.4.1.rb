# encoding: UTF-8

control "C-1.4.1" do
  title "Ensure AIDE is installed"
  desc  "AIDE takes a snapshot of filesystem state including modification
times, permissions, and file hashes which can then be used to compare against
the current state of the filesystem to detect modifications to the system."
  desc  "rationale", "By monitoring the filesystem state compromised files can
be detected to prevent or limit the exposure of accidental or malicious
misconfigurations or modified binaries."
  desc  "check", "
    Verify AIDE is installed:

    ```
    # dpkg -s aide
    ```
  "
  desc "fix", "
    Install AIDE using the appropriate package manager or manual installation:

    ```
    # apt install aide aide-common
    ```

    Configure AIDE as appropriate for your environment. Consult the AIDE
documentation for options.

    Initialize AIDE:

    ```
    # aideinit
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
  tag nist: ["AU-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.9", "Rev_7"]
  tag cis_rid: "1.4.1"

  describe package('aide') do
    it { should be_installed }
  end

  describe package('aide-common') do
    it { should be_installed }
  end
end
