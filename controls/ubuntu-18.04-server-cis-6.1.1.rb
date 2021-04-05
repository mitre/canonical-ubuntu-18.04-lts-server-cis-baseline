# encoding: UTF-8

control "C-6.1.1" do
  title "Audit system file permissions"
  desc  "The Ubuntu package manager has a number of useful options. One of
these, the `--verify` option, can be used to verify that system packages are
correctly installed. The `--verify` option can be used to verify a particular
package or to verify all system packages. If no output is returned, the package
is installed correctly. The following table describes the meaning of output
from the verify option:

    ```
    Code Meaning
    S File size differs.
    M File mode differs (includes permissions and file type).
    5 The MD5 checksum differs.
    D The major and minor version numbers differ on a device file.
    L A mismatch occurs in a link.
    U The file ownership differs.
    G The file group owner differs.
    T The file time (mtime) differs.
    ```

    The `dpkg -S` command can be used to determine which package a particular
file belongs to. For example the following command determines which package the
`/bin/bash` file belongs to:

    ```
    # dpkg -S /bin/bash

    bash: /bin/bash
    ```

    To verify the settings for the package that controls the `/bin/bash` file,
run the following:

    ```
    # dpkg --verify bash

    ??5?????? c /etc/bash.bashrc
    ```
  "
  desc  "rationale", "It is important to confirm that packaged system files and
directories are maintained with the permissions they were intended to have from
the OS vendor."
  desc  "check", "
    Run the following command to review all installed packages. Note that this
may be very time consuming and may be best scheduled via the `cron` utility. It
is recommended that the output of this command be redirected to a file that can
be reviewed later.

    ```
    # dpkg --verify

    ```
  "
  desc "fix", "Correct any discrepancies found and rerun the audit until
output is clean or risk is mitigated or accepted."
  impact 0.7
  tag severity: "high"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 2
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.1"

  cmd = 'dpkg --verify'
  describe command('dpkg --verify') do
    skip "This control must be reviewed manually. Run `#{cmd}` and review the results."
  end
end
