# encoding: UTF-8

control "C-4.2.2.2" do
  title "Ensure journald is configured to compress large log files"
  desc  "The journald system includes the capability of compressing overly
large files to avoid filling up the system with logs or making the logs
unmanageably large."
  desc  "rationale", "Uncompressed large files may unexpectedly fill a
filesystem leading to resource unavailability. Compressing logs prior to write
can prevent sudden, unexpected filesystem impacts."
  desc  "check", "
    Review `/etc/systemd/journald.conf` and verify that large files will be
compressed:

    ```
    # grep -E -i \"^\\s*Compress\" /etc/systemd/journald.conf

    Compress=yes
    ```
  "
  desc "fix", "
    Edit the `/etc/systemd/journald.conf` file and add the following line:

    ```
    Compress=yes
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
  tag nist: ["AU-4", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.4", "Rev_7"]
  tag cis_rid: "4.2.2.2"
end
