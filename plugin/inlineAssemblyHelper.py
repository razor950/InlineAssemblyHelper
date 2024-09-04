from __future__ import print_function

import idautils
import idc
import ida_idaapi
import ida_bytes
import ida_hexrays
import ida_lines
import re
import ida_kernwin
import ida_ua

from inline_assembly.instruction import instruction_dict
from inline_assembly.instruction_updater import scrape_instructions

class DisassemblyHoverHandler(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.popup = None

    def get_custom_viewer_hint(self, view, place):
        widget = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return None

        # Get the address from the place object
        ea = place.toea()

        # Decode the instruction at this address
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None

        # Get the mnemonic
        mnemonic = ida_ua.print_insn_mnem(ea).lower()
        
        if mnemonic in instruction_dict:
            description = instruction_dict[mnemonic]
            
            # Get operands
            operands = ida_lines.tag_remove(ida_ua.print_operand(ea, 0))
            if ida_ua.print_operand(ea, 1) != "":
                operands += ", " + ida_lines.tag_remove(ida_ua.print_operand(ea, 1))

            # Get any comments
            cmt = ida_bytes.get_cmt(ea, 0)
            if not cmt:
                cmt = ida_bytes.get_cmt(ea, 1)

            # Construct the hint text
            hint = f"{mnemonic} {operands}: {description}"
            if cmt:
                hint += f"\nComment: {cmt}"

            return (hint, 2)  # Return 2 lines of hint text

        return None

    def show_popup(self, view, popup_handle):
        self.popup = popup_handle

    def hide_popup(self):
        self.popup = None

class inline_assembly_hooks_t(ida_hexrays.Hexrays_Hooks):
    def func_printed(self, cfunc):
        inside_asm_block = False
        added_comments = set()

        for sl in cfunc.get_pseudocode():
            if "__asm" in sl.line:
                inside_asm_block = True

            if inside_asm_block:
                
                matches = re.finditer(r'\b([a-zA-Z_]\w*)\b', sl.line)                
                for match in matches:
                    instruction = match.group(1)
                    if instruction == "__asm":
                        continue
                    else:
                        clean_instruction_ = instruction

                        for mnemonic, definition in instruction_dict.items():
                            if clean_instruction_ == mnemonic or clean_instruction_[1:] == mnemonic:
                                if mnemonic not in added_comments:
                                    sl.line += f" // {definition}"
                                    added_comments.add(mnemonic)
                                    break
                        

                if "}" in sl.line:
                    inside_asm_block = False

        return 0

class inlineAssembly(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays Inline Assembly Helper (IDAPython)"
    wanted_hotkey = ""
    comment = "An IDAPython plugin that adds a comment for inline assembly"
    help = ""

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            scrape_instructions()
            self.inline_assembly_hooks = inline_assembly_hooks_t()
            self.inline_assembly_hooks.hook()
            
            # Initialize and hook the DisassemblyHoverHandler
            self.disasm_hover_handler = DisassemblyHoverHandler()
            self.disasm_hover_handler.hook()
            
            print("[InlineAssembly] Loaded plugin v0.0.3 -- Made with love by @0xdeadc0de___ & r00tz")
            return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if self.inline_assembly_hooks:
            self.inline_assembly_hooks.unhook()
        if self.disasm_hover_handler:
            self.disasm_hover_handler.unhook()

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return inlineAssembly()
