"""
Information flow analysis for the C0 subset.

Students must implement:
  check_secure(prog) - returns True if secure, False otherwise
"""

import c0
import sys

L = 0
H = 1


def join(a: int, b: int) -> int:
    return H if a == H or b == H else L

class IFCError(Exception):
    pass

# Set the label for the variable either H or L
def set_var_label(label: str | None) -> int:
    if label == "H":
        return H
    return L

class Checker:
    def __init__(self, prog: c0.Program):
      self.prog = prog
      self.env: list[dict[str, tuple[c0.Type, int]]] = [
          {
              "input": (c0.IntType(), L),
              "secret": (c0.IntType(), H),
          }
      ]
    
    def lookup(self, name: str) -> tuple[c0.Type, int]:
      for scope in reversed(self.env):
        if name in scope:
          return scope[name]
      raise IFCError(f"undeclared variable {name}")

    # Add var to current scope
    def declare(self, name: str, typ: c0.Type, level: int) -> None:
      self.env[-1][name] = (typ, level)

    # Matching from the c0.py file. We match these and return the value it should have
    def exp_info(self, e: c0.Exp) -> tuple[int, int]:
      match e:
        
        case c0.IntConst(_):
          return (L, L)
        
        case c0.BoolConst(_):
          return (L, L)
        
        case c0.Var(name):
          _, level = self.lookup(name)
          return (level, L)
        
        case c0.BinOp(op, left, right):
          vl, al = self.exp_info(left)
          vr, ar = self.exp_info(right)
          value = join(vl, vr)
          
          if op in ("/", "%"):
            abort = join(join(al, ar), vr)
            return (value, abort)
          
          if op in ("&&", "||"):
            abort = join(al, ar)
         
          else:
            abort = join(al, ar)
          
          return (value, abort)
        
        case c0.UnOp(op, arg):
          v, a = self.exp_info(arg)
          
          if op in ("!", "-"):
            return (v, a)
          raise IFCError(f"unsupported unary operator {op}")
        
        case c0.Length(arg):
          v, a = self.exp_info(arg)
          return (v, a)
        
        case c0.ArrayAccess(arr, index):
          va, aa = self.exp_info(arr)
          vi, ai = self.exp_info(index)
          value = join(va, vi)
          abort = join(aa, join(ai, vi))
          return (value, abort)
        
        case _:
          raise IFCError(f"unsupported expression form {type(e)}")

    def require_low_abort(self, abort_level: int) -> None:
      if abort_level != L:
        raise IFCError("abort depends on high data")

    # Matching from c0.py file. These are matched to the statment class
    def check_stmt(self, s: c0.Stmt, pc: int) -> None:
      match s:
        
        case c0.Decl(typ, name, init, label=label):
          level = set_var_label(label)
          self.declare(name, typ, level)
          
          if init is not None:
            v, a = self.exp_info(init)
            self.require_low_abort(a)
            
            if join(pc, v) > level:
              raise IFCError("illegal flow in declaration initializer")

        case c0.Assign(dest, source):
          _, dest_level = self.lookup(dest)
          v, a = self.exp_info(source)
          self.require_low_abort(a)
          
          if join(pc, v) > dest_level:
            raise IFCError("illegal flow in assignment")

        case c0.AllocArray(dest, _typ, count, label=_label):
          dest_type, dest_level = self.lookup(dest)
          
          if not isinstance(dest_type, c0.ArrayType):
            raise IFCError("alloc_array destination must be an array")
    
          v, a = self.exp_info(count)
          
          self.require_low_abort(a)

          if join(pc, v) > dest_level:
            raise IFCError("illegal flow in array allocation")
    
        case c0.ArrRead(dest, arr, index):
          _, dest_level = self.lookup(dest)
          _, arr_level = self.lookup(arr.name) if isinstance(arr, c0.Var) else (None, L)
          va, aa = self.exp_info(arr)
          vi, ai = self.exp_info(index)
          value = join(va, vi)
          abort = join(aa, join(ai, vi))
          if arr_level == L:
            self.require_low_abort(abort)
          
          if join(pc, value) > dest_level:
            raise IFCError("illegal flow in array read")

        case c0.ArrWrite(arr, index, val):
          if not isinstance(arr, c0.Var):
            raise IFCError("array write base must be a variable")
          _, arr_level = self.lookup(arr.name)
          vi, ai = self.exp_info(index)
          vw, aw = self.exp_info(val)
          if arr_level == L:
            self.require_low_abort(join(ai, vi))
          self.require_low_abort(aw)
          if join(pc, join(vi, vw)) > arr_level:
            raise IFCError("illegal flow in array write")

        case c0.Block(stmts):
          self.env.append({})
          try:
            for st in stmts:
              self.check_stmt(st, pc)
          finally:
            self.env.pop()

        case c0.If(cond, true_branch, false_branch):
          vc, ac = self.exp_info(cond)
          self.require_low_abort(ac)
          pc2 = join(pc, vc)
          self.check_stmt(true_branch, pc2)
          if false_branch is not None:
            self.check_stmt(false_branch, pc2)

        case c0.While(cond, _invariants, body):
          vc, ac = self.exp_info(cond)
          
          if pc != L or vc != L:
            raise IFCError("high-dependent loop")
          
          self.require_low_abort(ac)
          self.check_stmt(body, L)

        case c0.Assert(cond):
          vc, ac = self.exp_info(cond)
          if join(pc, join(vc, ac)) != L:
            raise IFCError("abort depends on high data")

        case c0.Error(_msg):
          if pc != L:
            raise IFCError("high-controlled abort")

        case c0.Return(val):
          if val is None:
            raise IFCError("return must have a value")
          v, a = self.exp_info(val)
          self.require_low_abort(a)
          if join(pc, v) != L:
            raise IFCError("return leaks high data")
      
        case _:
          raise IFCError(f"unsupported statement form {type(s)}")

    def check(self) -> bool:
      for st in self.prog.stmts:
        self.check_stmt(st, L)
      return True


def check_secure(prog: c0.Program) -> bool:
    """Termination-sensitive information flow type checker.

    Returns True if the program is secure, False otherwise.
    """
    try:
      return Checker(prog).check()
    except IFCError as e:
      try:
        print(f"[debug] stage=ifc_failed error={e}", file=sys.stderr, flush=True)
      except Exception:
        pass
      return False