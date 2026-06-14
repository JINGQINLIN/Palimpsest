/**
 * @name DHCP handler packet parameter type, where the handler reaches command exec
 * @description A/B probe for the reconstruction fix. Lists every handle_dhcp_*
 *              function that (transitively) reaches a command-execution call,
 *              together with the declared type of its first (packet) parameter.
 *              Before the chain-focused review the type is laundered to `int`,
 *              which severs taint at the call boundary; after, it is
 *              `struct dhcp_packet *`, so taint can follow the packet through.
 * @kind table
 * @id semant/packet-to-exec
 */

import cpp

predicate isExec(Function f) {
  f.hasName([
      "system", "___system", "popen", "execl", "execlp", "execle",
      "execv", "execvp", "execve", "posix_spawn", "posix_spawnp",
      "ExecShell", "CsteSystem", "doSystemCmd"
    ])
}

predicate reachesExec(Function f) {
  exists(FunctionCall fc | fc.getEnclosingFunction() = f and isExec(fc.getTarget()))
  or
  exists(FunctionCall fc | fc.getEnclosingFunction() = f and reachesExec(fc.getTarget()))
}

from Function handler, Parameter p, string param_type
where
  handler.getName().regexpMatch("handle_dhcp.*") and
  p = handler.getParameter(0) and
  param_type = p.getType().toString() and
  reachesExec(handler)
select handler.getName(), param_type, "reaches command-exec"
