UNIX Commands (1)
=================

Exploring the file system
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell

   ls                                   # List the contents of the current directory
   pwd                                  # Print working directory
   cd DIRECTORY_NAME                    # Change directory

Managing files
~~~~~~~~~~~~~~

.. code-block:: shell

    mkdir DIRECTORY_NAME                # Create directory (folder)
    mv SRC_FILENAME DEST_FILENAME       # Move and/or rename a file or directory
    touch FILENAME                      # Create an empty file
    cp SRC_FILENAME DEST_FILENAME       # Copy a file
    rm FILENAME                         # Remove a file
    rm -f FILENAME                      # Force to remove a file
    rm -rf DIRECTORY_NAME               # Remove a directory that contains files

Viewing files
~~~~~~~~~~~~~

.. code-block:: bash

    less FILENAME                       # Show file content, ( exit by typing "q" )
    cat FILENAME                        # Print file content

Misc
~~~~~~

.. code-block:: bash

    sudo COMMAND                        # Execute a command as root
    sudo shutdown -h 0                  # Shutdown the computer now