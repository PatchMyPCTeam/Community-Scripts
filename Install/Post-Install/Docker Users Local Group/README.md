## Add User to docker-users local group

After installing Docker it is required that the current user be added to the 'docker-users' local group in order to use Docker.

This script will take the current user based on the session owner of 'explorer.exe' and add to 'docker-users' group.