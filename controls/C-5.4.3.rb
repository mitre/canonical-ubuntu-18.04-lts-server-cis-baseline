# encoding: UTF-8

control "C-5.4.3" do
  title "Ensure default group for the root account is GID 0"
  desc  "The usermod command can be used to specify which group the root user
belongs to. This affects permissions of files that are created by the root
user."
  desc  "rationale", "Using GID 0 for the `root` account helps prevent `root`
-owned files from accidentally becoming accessible to non-privileged users."
  desc  "check", "
    Run the following command and verify the result is `0` :
    ```
    # grep \"^root:\" /etc/passwd | cut -f4 -d:
    0
    ```
  "
  desc  "fix", "
    Run the following command to set the `root` user default group to GID `0` :
    ```
    # usermod -g 0 root
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
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "5.4.3"
end
