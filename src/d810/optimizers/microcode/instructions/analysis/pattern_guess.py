import os
from collections import OrderedDict

import ida_hexrays

from d810.core import getLogger
from d810.expr.ast import minsn_to_ast
from d810.hexrays.hexrays_formatters import (
    count_minsn_nodes,
    format_minsn_t,
    format_mop_t,
    maturity_to_string,
    opcode_to_string,
)
from d810.optimizers.microcode.handler import DEFAULT_INSTRUCTION_MATURITIES
from d810.optimizers.microcode.instructions.analysis.handler import (
    InstructionAnalysisRule,
)
from d810.optimizers.microcode.instructions.analysis.utils import get_possible_patterns

optimizer_logger = getLogger("D810.optimizer")


class ExampleGuessingRule(InstructionAnalysisRule):
    DESCRIPTION = "Detect pattern with variable used multiple times and with multiple different opcodes"

    def __init__(self):
        super().__init__()
        self.maturities = DEFAULT_INSTRUCTION_MATURITIES
        self.cur_maturity = None
        self.min_nb_var = 1
        self.max_nb_var = 3
        self.min_nb_diff_opcodes = 3
        self.max_nb_diff_opcodes = -1

        self.cur_index = 0
        self.max_index = 1000
        # Remember EVERY analyzed instruction (hits and misses). Hex-Rays calls
        # us back on the same instruction many times per maturity (and across 5
        # maturities); re-running minsn_to_ast + get_possible_patterns on
        # non-matching instructions each time caused multi-minute hangs on
        # large OLLVM functions. The analysis is a pure function of the
        # formatted instruction, so caching it is safe.
        self.cur_ins_analyzed: OrderedDict[str, None] = OrderedDict()
        # Deeply nested MBA expressions explode the pattern enumeration; they
        # are also useless as guessing candidates. Skip them entirely.
        self.max_ins_nodes = 64
        self.pattern_filename_path = None

    def log_info(self, message: str):
        if self.pattern_filename_path is None:
            return
        with open(self.pattern_filename_path, "a") as f:
            f.write("{0}\n".format(message))

    def set_maturity(self, maturity):
        self.log_info(
            "Patterns guessed at maturity {0}".format(maturity_to_string(maturity))
        )
        self.cur_maturity = maturity

    def set_log_dir(self, log_dir):
        super().set_log_dir(log_dir)
        if self.log_dir is None:
            return
        self.pattern_filename_path = os.path.join(self.log_dir, "pattern_guess.log")
        open(self.pattern_filename_path, "w").close()

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_var" in kwargs.keys():
            self.min_nb_var = kwargs["min_nb_var"]
        if "max_nb_var" in kwargs.keys():
            self.max_nb_var = kwargs["max_nb_var"]
        if "min_nb_diff_opcodes" in kwargs.keys():
            self.min_nb_diff_opcodes = kwargs["min_nb_diff_opcodes"]
        if "max_nb_diff_opcodes" in kwargs.keys():
            self.max_nb_diff_opcodes = kwargs["max_nb_diff_opcodes"]

        if self.max_nb_var == -1:
            self.max_nb_var = 0xFF
        if self.max_nb_diff_opcodes == -1:
            self.max_nb_diff_opcodes = 0xFF
        if "max_ins_nodes" in kwargs.keys():
            self.max_ins_nodes = int(kwargs["max_ins_nodes"])

    def _remember_analyzed(self, formatted_ins: str) -> None:
        """Record an instruction as analyzed, evicting the oldest entry FIFO-style."""
        analyzed = self.cur_ins_analyzed
        analyzed[formatted_ins] = None
        if len(analyzed) > self.max_index:
            analyzed.popitem(last=False)
        self.cur_index = len(analyzed)

    def analyze_instruction(self, blk, ins) -> bool:
        if self.cur_maturity not in self.maturities:
            return False
        formatted_ins = str(format_minsn_t(ins))
        if formatted_ins in self.cur_ins_analyzed:
            return False
        if ins.opcode == ida_hexrays.m_nop:
            optimizer_logger.debug("Skipping pattern guess for nop instruction")
            return False
        if count_minsn_nodes(ins) > self.max_ins_nodes:
            optimizer_logger.debug(
                "Skipping pattern guess: instruction at 0x%x exceeds %d nodes",
                ins.ea,
                self.max_ins_nodes,
            )
            self._remember_analyzed(formatted_ins)
            return False

        tmp = minsn_to_ast(ins)
        if tmp is None:
            optimizer_logger.debug(
                "Skipping pattern guess: no AST for opcode %s",
                opcode_to_string(ins.opcode),
            )
            self._remember_analyzed(formatted_ins)
            return False
        is_good_candidate = self.check_if_possible_pattern(tmp)
        self._remember_analyzed(formatted_ins)
        return is_good_candidate

    def check_if_possible_pattern(self, test_ast) -> bool:
        patterns = get_possible_patterns(
            test_ast, min_nb_use=2, ref_ast_info_by_index=None, max_nb_pattern=64
        )
        for pattern in patterns:
            leaf_info_list, cst_leaf_values, opcodes = pattern.get_information()
            leaf_nb_use = [leaf_info.number_of_use for leaf_info in leaf_info_list]
            if not (self.min_nb_var <= len(leaf_info_list) <= self.max_nb_var):
                continue
            if not (
                self.min_nb_diff_opcodes
                <= len(set(opcodes))
                <= self.max_nb_diff_opcodes
            ):
                continue
            if not (min(leaf_nb_use) >= 2):
                continue
            ins = pattern.mop.d
            self.log_info("IR: 0x{0:x} - {1}".format(ins.ea, format_minsn_t(ins)))
            for leaf_info in leaf_info_list:
                self.log_info(
                    "  {0} -> {1}".format(
                        leaf_info.ast, format_mop_t(leaf_info.ast.mop)
                    )
                )
            self.log_info("Pattern: {0}".format(pattern))
            self.log_info("AstNode: {0}\n".format(pattern.get_pattern()))
            return True
        return False
