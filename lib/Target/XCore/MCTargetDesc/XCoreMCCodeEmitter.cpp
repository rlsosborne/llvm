//===-- XCoreMCCodeEmitter.cpp - Convert XCore code to machine code -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the XCoreMCCodeEmitter class.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/XCoreMCTargetDesc.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInstrInfo.h"

using namespace llvm;

#define DEBUG_TYPE "mccodeemitter"

namespace {
class XCoreMCCodeEmitter : public MCCodeEmitter {
  const MCInstrInfo &MCII;
  MCContext &Ctx;

public:
  XCoreMCCodeEmitter(const MCInstrInfo &mcii, MCContext &ctx)
    : MCII(mcii), Ctx(ctx) {
  }

  ~XCoreMCCodeEmitter() {}

  // Override MCCodeEmitter.
  void EncodeInstruction(const MCInst &MI, raw_ostream &OS,
                         SmallVectorImpl<MCFixup> &Fixups,
                         const MCSubtargetInfo &STI) const override;

private:
  // Automatically generated by TableGen.
  uint64_t getBinaryCodeForInstr(const MCInst &MI,
                                 SmallVectorImpl<MCFixup> &Fixups,
                                 const MCSubtargetInfo &STI) const;

  unsigned PostEncode2RInstruction(const MCInst &MI, unsigned EncodedValue,
                                   const MCSubtargetInfo &STI) const;

  /// getMachineOpValue - Return binary encoding of operand. If the machine
  /// operand requires relocation, record the relocation and return zero.
  unsigned getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                             SmallVectorImpl<MCFixup> &Fixups,
                             const MCSubtargetInfo &STI) const;
};
} // end anonymous namespace

MCCodeEmitter *llvm::createXCoreMCCodeEmitter(const MCInstrInfo &MCII,
                                              const MCRegisterInfo &MRI,
                                              const MCSubtargetInfo &MCSTI,
                                              MCContext &Ctx) {
  return new XCoreMCCodeEmitter(MCII, Ctx);
}

void XCoreMCCodeEmitter::
EncodeInstruction(const MCInst &MI, raw_ostream &OS,
                  SmallVectorImpl<MCFixup> &Fixups,
                  const MCSubtargetInfo &STI) const {
  uint64_t Bits = getBinaryCodeForInstr(MI, Fixups, STI);
  unsigned Size = MCII.get(MI.getOpcode()).getSize();
  // Little-endian insertion of Size bytes.
  for (unsigned I = 0; I != Size; ++I) {
    OS << uint8_t(Bits >> (I * 8));
  }
}

/// getMachineOpValue - Return binary encoding of operand. If the machine
/// operand requires relocation, record the relocation and return zero.
unsigned
XCoreMCCodeEmitter::getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                                      SmallVectorImpl<MCFixup> &Fixups,
                                      const MCSubtargetInfo &STI) const {
  if (MO.isReg())
    return Ctx.getRegisterInfo()->getEncodingValue(MO.getReg());

  assert(MO.isImm() && "did not expect relocated expression");
  return static_cast<unsigned>(MO.getImm());
}

unsigned XCoreMCCodeEmitter::
PostEncode2RInstruction(const MCInst &MI, unsigned EncodedValue,
                        const MCSubtargetInfo &STI) const {
  SmallVector<MCFixup, 1> Fixups;
  unsigned Op1Value = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
  unsigned Op2Value = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
  EncodedValue |= Op2Value & 3;
  EncodedValue |= (Op1Value & 3) << 2;
  unsigned Combined = (Op1Value >> 2) + (Op1Value >> 2) * 3;
  if (Combined < 27)
    Combined += 27;
  EncodedValue |= (Combined >> 5) << 5;
  EncodedValue |= (Combined & 31) << 6;
  return EncodedValue;
}

#include "XCoreGenMCCodeEmitter.inc"
