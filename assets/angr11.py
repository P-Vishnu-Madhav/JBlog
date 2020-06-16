import angr
import claripy
import sys
proj=angr.Project('/home/madhav/Documents/Bi0s-Challenges/Reverse Engineering/Reversingtasks-9-AngrCTF/11_angr_sim_scanf')
state=proj.factory.entry_state()
class Replacement(angr.SimProcedure):
    def run(self,format_string,scanf0_addr,scanf1_addr):
        scanf0_addr=0x804fd73
        scanf1_addr=0x804fd73
        scanf0=claripy.BVS('scanf0',32)
        scanf1=claripy.BVS('scanf1',32)
        self.state.memory.store(scanf0_addr,scanf0)
        self.state.memory.store(scanf1_addr,scanf1)
        