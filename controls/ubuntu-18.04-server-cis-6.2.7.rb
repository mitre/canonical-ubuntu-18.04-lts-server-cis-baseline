# encoding: UTF-8

control "C-6.2.7" do
  title "Ensure root PATH Integrity"
  desc  "The `root` user can execute any command on the system and could be
fooled into executing programs unintentionally if the `PATH` is not set
correctly."
  desc  "rationale", "Including the current working directory (.) or other
writable directory in `root` 's executable path makes it likely that an
attacker can gain superuser access by forcing an administrator operating as
`root` to execute a Trojan horse program."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    if echo \"$PATH\" | grep -q \"::\" ; then
     echo \"Empty Directory in PATH (::)\"
    fi
    if echo \"$PATH\" | grep -q \":$\" ; then
     echo \"Trailing : in PATH\"
    fi
    for x in $(echo \"$PATH\" | tr \":\" \" \") ; do
     if [ -d \"$x\" ] ; then
     ls -ldH \"$x\" | awk '
     $9 == \".\" {print \"PATH contains current working directory (.)\"}
     $3 != \"root\" {print $9, \"is not owned by root\"}
     substr($1,6,1) != \"-\" {print $9, \"is group writable\"}
     substr($1,9,1) != \"-\" {print $9, \"is world writable\"}'
     else
     echo \"$x is not a directory\"
     fi
    done
    ```
  "
  desc "fix", "Correct or justify any items discovered in the Audit step."
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.7"

  describe "root $PATH" do
    skip "This control must be reviewed manually using the documented check."
  end
end
