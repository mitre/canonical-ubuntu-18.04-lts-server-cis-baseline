# encoding: UTF-8

control "C-6.1.10" do
  title "Ensure no world writable files exist"
  desc  "Unix-based systems support variable settings to control access to
files. World writable files are the least secure. See the `chmod(2)` man page
for more information."
  desc  "rationale", "Data in world-writable files can be modified and
compromised by any user on the system. World writable files may also indicate
an incorrectly written script or program that could potentially be the cause of
a larger compromise to the system's integrity."
  desc  "check", "
    Run the following command and verify no files are returned:

    ```
    # df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}'
-xdev -type f -perm -0002
    ```

    The command above only searches local filesystems, there may still be
compromised items on network mounted partitions. Additionally the `--local`
option to `df` is not universal to all versions, it can be omitted to search
all filesystems on a system including network mounted filesystems or the
following command can be run manually for each partition:

    ```
    # find

    \t -xdev -type f -perm -0002
    ```
  "
  desc "fix", "Removing write access for the \"other\" category ( `chmod o-w `
) is advisable, but always consult relevant vendor documentation to avoid
breaking any application dependencies on a given file."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.10"

  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002") do
    its('stdout') { should be_empty }
  end
end
