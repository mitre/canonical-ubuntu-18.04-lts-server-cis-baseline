# encoding: UTF-8

control "C-1.3.3" do
  title "Ensure sudo log file exists"
  desc  "sudo can use a custom log file"
  desc  "rationale", "A sudo log file simplifies auditing of sudo commands"
  desc  "check", "
    Verify that sudo has a custom log file configured

    Run the following command:

    ```
    # grep -Ei '^\\s*Defaults\\s+logfile=\\S+' /etc/sudoers /etc/sudoers.d/*
    ```

    verify output includes

    ```
    Defaults logfile=\"

    ```

    Where `

    \t` Is a file location that conforms with local site policy
  "
  desc "fix", "
    edit the file `/etc/sudoers` or a file in `/etc/sudoers.d/` and add the
following line:

    ```
    Defaults logfile=\"

    \t\"
    ```

    **Example**

    ```
    Defaults logfile=\"/var/log/sudo.log\"
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
  tag nist: ["AU-3", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.3", "Rev_7"]
  tag cis_rid: "1.3.3"


  describe command("grep -Ei '^\\s*Defaults\\s+([^#]+,\\s*)?logfile=(,\\s+\\S+\\s*)*(\\s+#.*)?' /etc/sudoers /etc/sudoers.d/*").stdout.strip.split("\n") do
    its('length') { should be > 0 }
  end


end
