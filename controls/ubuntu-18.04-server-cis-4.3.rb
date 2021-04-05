# encoding: UTF-8

control "C-4.3" do
  title "Ensure logrotate is configured"
  desc  "The system includes the capability of rotating log files regularly to
avoid filling up the system with logs or making the logs unmanageably large.
The file `/etc/logrotate.d/rsyslog` is the configuration file used to rotate
log files created by `rsyslog`."
  desc  "rationale", "By keeping the log files smaller and more manageable, a
system administrator can easily archive these files to another system and spend
less time looking through inordinately large log files."
  desc  "check", "Review `/etc/logrotate.conf` and `/etc/logrotate.d/rsyslog`
and verify logs are rotated according to site policy."
  desc  "fix", "Edit `/etc/logrotate.conf` and `/etc/logrotate.d/rsyslog` to
ensure logs are rotated according to site policy."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AU-4"]
  tag cis_level: 1
  tag cis_controls: ["6.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.3"

  describe "/etc/logrotate.conf and /etc/logrotate.d/rsyslog" do
    skip "This control must be reviewed manually using the documented check."
  end
end
