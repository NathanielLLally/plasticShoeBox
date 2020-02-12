/*
 * instruction class definition
 *
 * TODO: account for signed values
 *       account for > 32bit
 */

#include <glib.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

class dpfInstruction
{
 private:
  typedef struct _dpfOperand {
    GString *gs;
    GString *gsType;
    guint64 lVal;
  } dpfOperand;

  GString *gs;
  dpfOperand **op;
  guint8 iNumOps;
  void parseDisassembly(char *disBuf);

 public:
  dpfInstruction();
  dpfInstruction(char *disBuf);
  ~dpfInstruction();
  char *getInsn();
  guint8 numOps();
  char *getOp(guint8 opI);
  gboolean isVal(guint8 opI);
  guint64  getVal(guint8 opI);
  char *getType(guint8 opI);
  char *getCombined();
};
