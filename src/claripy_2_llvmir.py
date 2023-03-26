
import angr
import claripy
from llvmlite import ir
import llvmlite.binding as llvm
unop_llvm = {
    '__invert__':ir.IRBuilder.not_,
    '__neg__':ir.IRBuilder.neg
}
binop_llvm = {
    '__add__':ir.IRBuilder.add,
    '__floordiv__':ir.IRBuilder.udiv,
    'SDiv':ir.IRBuilder.sdiv,
    '__mul__':ir.IRBuilder.mul,
    '__sub__':ir.IRBuilder.sub,
    '__mod__':ir.IRBuilder.urem,
    'SMod':ir.IRBuilder.srem,
    '__and__':ir.IRBuilder.and_,
    '__or__':ir.IRBuilder.or_,
    '__xor__':ir.IRBuilder.xor,
    '__lshift__':ir.IRBuilder.shl,
    '__rshift__':ir.IRBuilder.ashr,
    'LShR':ir.IRBuilder.lshr
}
signed_op = ['SDiv','SMod']
supported_op = ['Concat','ZeroExt','SignExt','Extract','RotateLeft','RotateRight'] + list(unop_llvm.keys()) + list(binop_llvm.keys())
supported_type = ['BVV','BVS']
class lifter:
    def __init__(self):
        self.expr = None
        self.cur = None
        self.count = 0
        self.value_array = []
        self.builder = None
        self.func = None
        self.args = {}  
        self.node_count = 0
 
    def new_value(self, value, expr):
        assert value.type.width == expr.size()
        n = self.count
        self.value_array.append(value)
        self.count += 1
        return n
 
    def get_value(self, idx):
        return self.value_array[idx]
 
    def _visit_value(self, expr):
        if expr.op == 'BVV':
            self.cur = self.new_value(ir.Constant(ir.IntType(expr.size()), expr.args[0]), expr)
            #self.cur = self.new_value(ir.Constant(ir.ArrayType(ir.IntType(8), expr.size()/8), expr.args[0]), expr)
        else:
            self.cur = self.new_value(self.func.args[self.args[expr]], expr)
        pass
 
    def _visit_binop(self, expr):
        left = None
        for a in expr.args:
            self._visit_ast(a)
            if left is None:
                left = self.cur
            else:
                v = self.cur
                lhs = self.get_value(left)
                rhs = self.get_value(v)
                self.cur = self.new_value(binop_llvm[expr.op](self.builder, lhs, rhs, name = "node" + str(self.node_count)), expr)
                left = self.cur
                self.node_count += 1
        pass
 
    def _visit_unop(self, expr):
        self._visit_ast(expr.args[0])
        v0 = self.cur
        self.cur = self.new_value(unop_llvm[expr.op](self.builder, self.get_value(v0), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_concat(self, expr):
        left = None
        for a in expr.args:
            self._visit_ast(a)
            if left is None:
                left = self.cur
            else:
                v = self.cur
                lens = self.get_value(left).type.width + self.get_value(v).type.width
                val0 = self.builder.zext(self.get_value(left), ir.IntType(lens))
                val1 = self.builder.zext(self.get_value(v), ir.IntType(lens))
                self.cur = self.new_value(self.builder.or_(self.builder.shl(val0, ir.Constant(ir.IntType(lens), self.get_value(v).type.width)), val1, name = "node" + str(self.node_count)), expr)
                left = self.cur
                self.node_count += 1
        pass
 
 
    def get_bit_mask(self, low, high):
        mask = 0
        for i in range(low, high + 1):
            mask += 2 ** i
        return mask
 
    def _visit_extract(self, expr):
        high = expr.args[0]
        low = expr.args[1]
        self._visit_ast(expr.args[2])
        v0 = self.cur
        val = self.get_value(v0)
        mask = self.get_bit_mask(low, high)
        self.cur = self.new_value(self.builder.trunc(self.builder.lshr(self.builder.and_(val, ir.Constant(val.type, mask)), ir.Constant(val.type, low)), ir.IntType(high - low + 1), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_zeroext(self, expr):
        length = expr.args[0]
        self._visit_ast(expr.args[1])
        v0 = self.cur
        self.cur = self.new_value(self.builder.zext(self.get_value(v0), ir.IntType(length + expr.args[1].size()), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_signext(self, expr):
        length = expr.args[0]
        self._visit_ast(expr.args[1])
        v0 = self.cur
        self.cur = self.new_value(self.builder.sext(self.get_value(v0), ir.IntType(length + expr.args[1].size()), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_rotateleft(self, expr):
        bit = expr.args[1]
        self._visit_ast(expr.args[0])
        v0 = self.cur
        val = self.get_value(v0)
        width = val.type.width
        self.cur = self.new_value(self.builder.or_(self.builder.lshr(val, ir.Constant(val.type, width - bit)), self.builder.shl(val.type, ir.Constant(val.type, bit)), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_rotateright(self, expr):
        bit = expr.args[1]
        self._visit_ast(expr.args[0])
        v0 = self.cur
        val = self.get_value(v0)
        width = val.type.width
        self.cur = self.new_value(self.builder.or_(self.builder.shl(val, ir.Constant(val.type, width - bit)), self.builder.lshr(val.type, ir.Constant(val.type, bit)), name = "node" + str(self.node_count)), expr)
        self.node_count += 1
        pass
 
    def _visit_op(self, expr):
        if expr.op in binop_llvm.keys():
            self._visit_binop(expr)
        elif expr.op in unop_llvm.keys():
            self._visit_unop(expr)
        else:
            func = getattr(self, '_visit_' + expr.op.lower())
            func(expr)
 
    def _visit_ast(self, expr):
        assert isinstance(expr, claripy.ast.base.Base)
        if expr.op in supported_op:
            self._visit_op(expr)
        elif expr.op in supported_type:
            self._visit_value(expr)
        else:
            raise Exception("unsupported operation!")
 
    def lift(self, expr):
        self.expr = expr
        self.count = 0
        self.value_array = []
        self.args = {}
        c = 0
        for i in expr.leaf_asts():
            if i.op == 'BVS':
                self.args[i] = c
                c += 1
        items = sorted(self.args.items(),key=lambda x:x[1])
        print("Function arguments: ")
        print(items)
        type_list = []
        for i in items:
            type_list.append(ir.IntType(i[0].size()))
        fnty = ir.FunctionType(ir.IntType(expr.size()), tuple(type_list))
        module = ir.Module(name=__file__)
        self.func = ir.Function(module, fnty, name="dump")
        block = self.func.append_basic_block(name="entry")
        self.builder = ir.IRBuilder(block)
        self._visit_ast(expr)
        self.builder.ret(self.get_value(self.cur))
        return str(module)