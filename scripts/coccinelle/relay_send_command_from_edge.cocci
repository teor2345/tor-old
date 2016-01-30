// Rename the function relay_send_command_from_edge_ and the definition
// relay_send_command_from_edge to relay_send_command_ and relay_send_command,
// respectively.


@relay_send_command_from_edge_function@
identifier fn =~ "^relay_send_command_from_edge_$";
@@
- fn
+ relay_send_command_

@relay_send_command_from_edge_definition@
identifier fn =~ "^relay_send_command_from_edge$";
@@
- fn
+ relay_send_command
