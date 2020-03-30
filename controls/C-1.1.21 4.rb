# encoding: UTF-8

control "C-1.1.21" do
  title "Ensure sticky bit is set on all world-writable directories"
  desc  "Setting the sticky bit on world writable directories prevents users
from deleting or renaming files in that directory that are not owned by them."
  desc  "rationale", "This feature prevents the ability to delete or rename
files in world writable directories (such as `/tmp` ) that are owned by another
user."
  desc  "check", "
    Run the following command to verify no world writable directories exist
without the sticky bit set:

    ```
    # df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}'
-xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null
    ```

    No output should be returned.
  "
  desc  "fix", "
    Run the following command to set the sticky bit on all world writable
directories:

    ```
    # df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}'
-xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | xargs -I '{}'
chmod a+t '{}'
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
  tag cis_rid: "1.1.21"
end
