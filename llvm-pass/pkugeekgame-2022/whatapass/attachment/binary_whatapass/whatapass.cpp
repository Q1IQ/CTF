#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"
#include <vector>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <fstream>

using namespace llvm;
using std::vector;

namespace
{
  struct Whatapass : public FunctionPass
  {
    static char ID;
    bool flag;

    Whatapass() : FunctionPass(ID) {}
    Whatapass(bool flag) : FunctionPass(ID) { this->flag = flag; }
    bool runOnFunction(Function &F);
  };

  struct note_struct
  {
    unsigned char *address;
    size_t size;
  } note;

  vector<unsigned char> immValues;

  int getRandom()
  {
    static bool randomInit = true;
    if (randomInit)
    {
      srand(time(NULL));
      randomInit = false;
    }
    return rand();
  }

  const std::string base64Chars = "ABCDEFGHIJKLMN0PQRSTuVWXYzadcbefghijk1mnopqrstUvwxy7Ol23456Z89+/";
  std::string base64Encode(const std::string &in)
  {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in)
    {
      val = (val << 8) + c;
      valb += 8;
      while (valb >= 0)
      {
        out.push_back(base64Chars[(val >> valb) & 0x3F]);
        valb -= 6;
      }
    }
    if (valb > -6)
      out.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
      out.push_back('=');
    return out;
  }

  bool menu(Function &f, BasicBlock &BB)
  {
    for (BasicBlock::iterator ins = BB.begin(); ins != BB.end(); ++ins)
    {
      if (CallInst *call = dyn_cast<CallInst>(ins))
      {
        Function *func = call->getCalledFunction();
        if (func == NULL)
          continue;
        llvm::StringRef calledName = func->getName();

        if (calledName == "wher3")
        {
          if (call->getNumArgOperands() < 1)
            continue;
          Value *arg = call->getArgOperand(0);
          if (ConstantInt *CI = dyn_cast<ConstantInt>(arg))
          {
            size_t size = CI->getSExtValue();
            if (size > 0x400)
              continue;
            note.address = (unsigned char *)malloc(size);
            note.size = size;
          }
        }

        else if (calledName == "wr1te")
        {
          if (call->getNumArgOperands() < 2)
            continue;
          if (note.address == 0)
            continue;
          Value *arg = call->getArgOperand(0);
          if (ConstantInt *CI = dyn_cast<ConstantInt>(arg))
          {
            size_t offset = CI->getSExtValue();
            if (offset >= note.size)
              continue;
            arg = call->getArgOperand(1);
            if (ConstantInt *CI = dyn_cast<ConstantInt>(arg))
            {
              size_t value = CI->getSExtValue();
              if (value >= immValues.size())
                continue;
              note.address[offset] = immValues[value];
            }
          }
        }

        else if (calledName == "re4d")
        {
          if (call->getNumArgOperands() < 1)
            continue;
          if (note.address == 0)
            continue;
          Value *arg = call->getArgOperand(0);
          if (ConstantInt *CI = dyn_cast<ConstantInt>(arg))
          {
            size_t offset = CI->getSExtValue();
            if (offset >= note.size)
              continue;
            immValues.push_back(note.address[offset]);
          }
        }

        else if (calledName == "c1ear")
        {
          if (note.address == 0)
            continue;
          free(note.address);
          note.address = 0;
          note.size = 0;
        }

        else if (calledName == "p4int")
        {
          size_t num;
          if (call->getNumArgOperands() < 1)
          {
            num = 0xff;
          }
          else
          {
            Value *arg = call->getArgOperand(0);
            if (ConstantInt *CI = dyn_cast<ConstantInt>(arg))
            {
              num = CI->getSExtValue();
            }
          }
          size_t n = 0;
          for (Function::iterator b = f.begin(); b != f.end() && n < num; ++b)
          {
            errs() << "BB: " << &*b << "\n";
            for (BasicBlock::iterator ins = b->begin(); ins != b->end() && n < num; ++ins)
            {
              errs() << "\tInst: " << &*ins << "\n";
              n += 1;
            }
          }
        }

        else if (calledName == "g1ft")
        {
          std::ifstream flag("/flag");
          std::string flagstr;
          std::getline(flag, flagstr);
          std::string flag_prefix = "flag for u: ";
          flagstr = flag_prefix + flagstr;
          std::string flag_base64 = base64Encode(flagstr);
        }
      }
    }
    return true;
  }

  bool Whatapass::runOnFunction(Function &F)
  {
    Function *f = &F;
    if (f->getName() == "m41n")
    {
      vector<BasicBlock *> origBB;
      BasicBlock *loopEntry;
      BasicBlock *loopEnd;
      LoadInst *load;
      SwitchInst *switchI;
      AllocaInst *switchVar;
      errs() << "What a pass! \n";
      for (Function::iterator bb = f->begin(), e = f->end(); bb != e; ++bb)
      {
        for (BasicBlock::iterator i = bb->begin(), e = bb->end(); i != e; ++i)
        {
          if (StoreInst *store = dyn_cast<StoreInst>(i))
          {
            for (User::op_iterator op = i->op_begin(), e = i->op_end(); op != e; ++op)
            {
              if (ConstantInt *ci = dyn_cast<ConstantInt>(op))
              {
                immValues.push_back(ci->getSExtValue());
              }
            }
          }
        }
      }
      for (Function::iterator i = f->begin(); i != f->end(); ++i)
      {
        BasicBlock *tmp = &*i;
        origBB.push_back(tmp);
        BasicBlock *bb = &*i;

        if (isa<InvokeInst>(bb->getTerminator()))
        {
          return false;
        }
      }

      if (origBB.size() <= 0)
      {
        return false;
      }

      menu(F, *origBB[0]);
      if (origBB.size() <= 1)
      {

        return false;
      }

      origBB.erase(origBB.begin());

      Function::iterator tmp = f->begin();
      BasicBlock *insert = &*tmp;

      BranchInst *br = NULL;
      if (isa<BranchInst>(insert->getTerminator()))
      {
        br = cast<BranchInst>(insert->getTerminator());
      }

      if ((br != NULL && br->isConditional()) ||
          insert->getTerminator()->getNumSuccessors() > 1)
      {
        BasicBlock::iterator i = insert->end();
        --i;

        if (insert->size() > 1)
        {
          --i;
        }

        BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
        origBB.insert(origBB.begin(), tmpBB);
      }

      insert->getTerminator()->eraseFromParent();

      int randomKey = getRandom();
      switchVar =
          new AllocaInst(Type::getInt32Ty(f->getContext()), 0, "switchVar", insert);
      new StoreInst(
          ConstantInt::get(Type::getInt32Ty(f->getContext()),
                           randomKey),
          switchVar, insert);

      loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);

      loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

      load = new LoadInst(switchVar, "switchVar", loopEntry);

      insert->moveBefore(loopEntry);

      BranchInst::Create(loopEntry, insert);

      BranchInst::Create(loopEntry, loopEnd);

      BasicBlock *swDefault =
          BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
      BranchInst::Create(loopEnd, swDefault);

      switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);
      switchI->setCondition(load);

      f->begin()->getTerminator()->eraseFromParent();

      BranchInst::Create(loopEntry, &*f->begin());

      for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
           ++b)
      {

        BasicBlock *i = *b;
        ConstantInt *numCase = NULL;

        i->moveBefore(loopEnd);

        numCase = cast<ConstantInt>(ConstantInt::get(
            switchI->getCondition()->getType(), randomKey));
        switchI->addCase(numCase, i);
        randomKey = getRandom();
      }

      for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
           ++b)
      {
        BasicBlock *i = *b;
        ConstantInt *numCase = NULL;
        menu(F, *i);
        if (i->getTerminator()->getNumSuccessors() == 0)
        {
          continue;
        }

        if (i->getTerminator()->getNumSuccessors() == 1)
        {
          BasicBlock *succ = i->getTerminator()->getSuccessor(0);
          i->getTerminator()->eraseFromParent();
          numCase = switchI->findCaseDest(succ);
          new StoreInst(numCase, load->getPointerOperand(), i);
          BranchInst::Create(loopEnd, i);
          continue;
        }

        if (i->getTerminator()->getNumSuccessors() == 2)
        {
          ConstantInt *numCaseTrue =
              switchI->findCaseDest(i->getTerminator()->getSuccessor(0));
          ConstantInt *numCaseFalse =
              switchI->findCaseDest(i->getTerminator()->getSuccessor(1));

          BranchInst *br = cast<BranchInst>(i->getTerminator());
          SelectInst *sel =
              SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "",
                                 i->getTerminator());

          i->getTerminator()->eraseFromParent();

          auto *buf = new StoreInst(sel, load->getPointerOperand(), i);
          BranchInst::Create(loopEnd, i);

          delete buf;
          continue;
        }
      }
    }
    return true;
  }
}
char Whatapass::ID = 0;

static RegisterPass<Whatapass> X("Whatapass", "What a pass");
