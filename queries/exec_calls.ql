import cpp

predicate isExecutionFunction(Function f) {
  // 常见命令执行入口和固件封装函数。
  f.hasName("system") or
  f.hasName("___system") or
  f.hasName("popen") or
  f.hasName("execl") or
  f.hasName("execlp") or
  f.hasName("execle") or
  f.hasName("execv") or
  f.hasName("execvp") or
  f.hasName("execve") or
  f.hasName("posix_spawn") or
  f.hasName("posix_spawnp") or
  f.hasName("ExecShell") or
  f.hasName("CsteSystem") or
  f.hasName("doSystemCmd")
}

from FunctionCall call, Function target, Function caller
where
  call.getTarget() = target and
  isExecutionFunction(target) and
  caller = call.getEnclosingFunction()
select
  call,
  call.getFile().getRelativePath() as file,
  call.getLocation().getStartLine() as line,
  caller.getName() as caller_name,
  target.getName() as target_name,
  call.toString() as expression
