node_id=$(( $RANDOM % 2 + 1 ))
vagrant ssh "node-$node_id" -c "sudo ./add-student-user-script.sh \"$(($node_id + 3))022\""

exit 0
