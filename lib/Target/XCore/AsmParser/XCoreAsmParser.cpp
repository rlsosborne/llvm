//===-- XCoreAsmParser.cpp - Parse XCore assembly instructions ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/XCoreMCTargetDesc.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetAsmParser.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

namespace {

class XCoreOperand : public MCParsedAsmOperand {
  enum OperandKind {
    KindToken,
    KindReg,
    KindImm
  };

  OperandKind Kind;
  SMLoc StartLoc, EndLoc;

  // A string of length Length, starting at Data.
  struct TokenOp {
    const char *Data;
    unsigned Length;
  };

  union {
    TokenOp Token;
    unsigned RegNum;
    const MCExpr *Imm;
  };

public:
  XCoreOperand(OperandKind kind, SMLoc startLoc, SMLoc endLoc)
      : Kind(kind), StartLoc(startLoc), EndLoc(endLoc) {}

  // Create particular kinds of operand.
  static std::unique_ptr<XCoreOperand> createToken(StringRef Str, SMLoc Loc) {
    auto Op = make_unique<XCoreOperand>(KindToken, Loc, Loc);
    Op->Token.Data = Str.data();
    Op->Token.Length = Str.size();
    return Op;
  }
  static std::unique_ptr<XCoreOperand>
  createReg(unsigned Num, SMLoc StartLoc, SMLoc EndLoc) {
    auto Op = make_unique<XCoreOperand>(KindReg, StartLoc, EndLoc);
    Op->RegNum = Num;
    return Op;
  }
  static std::unique_ptr<XCoreOperand>
  createImm(const MCExpr *Expr, SMLoc StartLoc, SMLoc EndLoc) {
    auto Op = make_unique<XCoreOperand>(KindImm, StartLoc, EndLoc);
    Op->Imm = Expr;
    return Op;
  }

  // Token operands
  bool isToken() const override {
    return Kind == KindToken;
  }
  StringRef getToken() const {
    assert(Kind == KindToken && "Not a token");
    return StringRef(Token.Data, Token.Length);
  }

  // Register operands.
  bool isReg() const override {
    return Kind == KindReg;
  }
  unsigned getReg() const override {
    assert(Kind == KindReg && "Not a register");
    return RegNum;
  }

  // Immediate operands.
  bool isImm() const override {
    return Kind == KindImm;
  }
  const MCExpr *getImm() const {
    assert(Kind == KindImm && "Not an immediate");
    return Imm;
  }

  // Memory operands.
  bool isMem() const override {
    // TODO
    return false;
  }

  // Override MCParsedAsmOperand.
  SMLoc getStartLoc() const override { return StartLoc; }
  SMLoc getEndLoc() const override { return EndLoc; }
  void print(raw_ostream &OS) const override;

  // Used by the TableGen code to add particular types of operand
  // to an instruction.
  void addRegOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands");
    Inst.addOperand(MCOperand::CreateReg(getReg()));
  }
  void addImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands");
    // Add as immediates when possible.  Null MCExpr = 0.
    auto Expr = getImm();
    if (!Expr)
      Inst.addOperand(MCOperand::CreateImm(0));
    else if (auto *CE = dyn_cast<MCConstantExpr>(Expr))
      Inst.addOperand(MCOperand::CreateImm(CE->getValue()));
    else
      Inst.addOperand(MCOperand::CreateExpr(Expr));
  }
};

class XCoreAsmParser : public MCTargetAsmParser {
#define GET_ASSEMBLER_HEADER
#include "XCoreGenAsmMatcher.inc"

private:
  MCSubtargetInfo &STI;
  MCAsmParser &Parser;

  struct Register {
    unsigned Num;
    SMLoc StartLoc, EndLoc;
  };

  SMLoc getLoc() const { return Parser.getTok().getLoc(); }
  bool parseOperand(OperandVector &Operands, StringRef Mnemonic);
  bool tryParseRegister(Register &reg);
public:
  XCoreAsmParser(MCSubtargetInfo &sti, MCAsmParser &parser,
                 const MCInstrInfo &MII, const MCTargetOptions &Options)
      : MCTargetAsmParser(), STI(sti), Parser(parser) {
  }

  // Override MCTargetAsmParser.
  bool ParseDirective(AsmToken DirectiveID) override;
  bool ParseRegister(unsigned &RegNo, SMLoc &StartLoc, SMLoc &EndLoc) override;
  bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                        SMLoc NameLoc, OperandVector &Operands) override;
  bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                               OperandVector &Operands, MCStreamer &Out,
                               uint64_t &ErrorInfo,
                               bool MatchingInlineAsm) override;
};
} // end anonymous namespace

#define GET_REGISTER_MATCHER
#define GET_SUBTARGET_FEATURE_NAME
#define GET_MATCHER_IMPLEMENTATION
#include "XCoreGenAsmMatcher.inc"

bool XCoreAsmParser::ParseDirective(AsmToken DirectiveID) {
  return true;
}

static unsigned MatchRegisterName(StringRef Name);

bool XCoreAsmParser::tryParseRegister(Register &Reg) {
  Reg.StartLoc = Parser.getTok().getLoc();

  // Expect a register name.
  if (Parser.getTok().isNot(AsmToken::Identifier))
    return true;

  unsigned RegNum = MatchRegisterName(Parser.getTok().getString());
  if (RegNum == 0)
    return true;

  Parser.Lex();
  Reg.Num = RegNum;
  Reg.EndLoc = Parser.getTok().getLoc();
  return false;
}

bool XCoreAsmParser::ParseRegister(unsigned &RegNo, SMLoc &StartLoc,
                                   SMLoc &EndLoc) {
  // Expect a register name.
  Register Reg;
  if (tryParseRegister(Reg))
    return Error(getLoc(), "invalid register");

  RegNo = Reg.Num;
  StartLoc = Reg.StartLoc;
  EndLoc = Reg.EndLoc;
  return false;
}

bool XCoreAsmParser::parseOperand(OperandVector &Operands,
                                  StringRef Mnemonic) {
  // Check for a register.
  Register Reg;
  if (!tryParseRegister(Reg)) {
    Operands.push_back(XCoreOperand::createReg(Reg.Num, Reg.StartLoc,
                       Reg.EndLoc));
    return false;
  }

  switch(getLexer().getKind()) {
    case AsmToken::Integer: {
      SMLoc StartLoc = getLoc();
      const MCExpr *Expr;
      if (getParser().parseExpression(Expr))
        return true;
      SMLoc EndLoc =
        SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
      Operands.push_back(XCoreOperand::createImm(Expr, StartLoc, EndLoc));
      return false;
    }
    default:
      return true;
  }
}

bool XCoreAsmParser::ParseInstruction(ParseInstructionInfo &Info,
                                      StringRef Name, SMLoc NameLoc,
                                      OperandVector &Operands) {
  Operands.push_back(XCoreOperand::createToken(Name, NameLoc));

  // Read the remaining operands.
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    // Read the first operand.
    if (parseOperand(Operands, Name)) {
      Parser.eatToEndOfStatement();
      return true;
    }

    // Read any subsequent operands.
    while (getLexer().is(AsmToken::Comma)) {
      Parser.Lex();
      if (parseOperand(Operands, Name)) {
        Parser.eatToEndOfStatement();
        return true;
      }
    }
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
      SMLoc Loc = getLexer().getLoc();
      Parser.eatToEndOfStatement();
      return Error(Loc, "unexpected token in argument list");
    }
  }

  // Consume the EndOfStatement.
  Parser.Lex();
  return false;
}

void XCoreOperand::print(raw_ostream &OS) const {
  llvm_unreachable("Not implemented");
}

bool XCoreAsmParser::MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                             OperandVector &Operands,
                                             MCStreamer &Out,
                                             uint64_t &ErrorInfo,
                                             bool MatchingInlineAsm) {
  MCInst Inst;
  unsigned MatchResult;

  MatchResult = MatchInstructionImpl(Operands, Inst, ErrorInfo,
                                     MatchingInlineAsm);
  switch (MatchResult) {
  default: break;
  case Match_Success:
    Inst.setLoc(IDLoc);
    Out.EmitInstruction(Inst, STI);
    return false;

  case Match_MissingFeature: {
    assert(ErrorInfo && "Unknown missing feature!");
    // Special case the error message for the very common case where only
    // a single subtarget feature is missing
    std::string Msg = "instruction requires:";
    uint64_t Mask = 1;
    for (unsigned I = 0; I < sizeof(ErrorInfo) * 8 - 1; ++I) {
      if (ErrorInfo & Mask) {
        Msg += " ";
        Msg += getSubtargetFeatureName(ErrorInfo & Mask);
      }
      Mask <<= 1;
    }
    return Error(IDLoc, Msg);
  }

  case Match_InvalidOperand: {
    SMLoc ErrorLoc = IDLoc;
    if (ErrorInfo != ~0ULL) {
      if (ErrorInfo >= Operands.size())
        return Error(IDLoc, "too few operands for instruction");

      ErrorLoc = ((XCoreOperand &)*Operands[ErrorInfo]).getStartLoc();
      if (ErrorLoc == SMLoc())
        ErrorLoc = IDLoc;
    }
    return Error(ErrorLoc, "invalid operand for instruction");
  }

  case Match_MnemonicFail:
    return Error(IDLoc, "invalid instruction");
  }

  llvm_unreachable("Unexpected match type");
}

// Force static initialization.
extern "C" void LLVMInitializeXCoreAsmParser() {
  RegisterMCAsmParser<XCoreAsmParser> X(TheXCoreTarget);
}
