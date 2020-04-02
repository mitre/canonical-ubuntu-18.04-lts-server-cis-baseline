# encoding: UTF-8

control "C-1.3.2" do
  title "Ensure sudo commands use pty"
  desc  "sudo can be configured to run only from a psuedo-pty"
  desc  "rationale", "Attackers can run a malicious program using sudo, which
would again fork a background process that remains even when the main program
has finished executing."
  desc  "check", "
    Verify that sudo can only run other commands from a psuedo-pty

    Run the following command:

    ```
    # grep -Ei
'^\\s*Defaults\\s+([^#]+,\\s*)?use_pty(,\\s+\\S+\\s*)*(\\s+#.*)?$' /etc/sudoers
/etc/sudoers.d/*

    Defaults use_pty
    ```
  "
  desc "fix", "
    edit the file `/etc/sudoers` or a file in `/etc/sudoers.d/` and add the
following line:

    ```
    Defaults use_pty
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
  tag nist: ["AC-6 (9)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.3", "Rev_7"]
  tag cis_rid: "1.3.2"

  describe command("grep -Ei '^\\s*Defaults\\s+([^#]+,\\s*)?use_pty(,\\s+\\S+\\s*)*(\\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*").stdout.strip.split("\n") do
    its('length') { should be > 0 }
  end

end
