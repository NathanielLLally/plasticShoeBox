/*
 * Instruction class designed for parsing ndisasm's
 *   output for pseudo execution
 *
 * TODO: seperate memory initialization from parseDisassembly
 */

#include "priv.h"
#include "dpfInstruction.h"

dpfInstruction::dpfInstruction()
{
  iNumOps = 0;
  op = g_new(dpfOperand *, 2);
}

dpfInstruction::dpfInstruction(char *disBuf)
{
  iNumOps = 0;
  op = g_new(dpfOperand *, 2);
  parseDisassembly(disBuf);
}

//extract instruction and operand portions of outbuf
void dpfInstruction::parseDisassembly(char *disBuf)
{
  char *iSpc = NULL, *iCom = NULL;
  char *iType = NULL, *buf = NULL;

  //                   tab, newline, nul
  const char remDel[] = {0x09, 0x10, 0x0};

  const char *matchType[] = {
    {"short"},
    {"near"},
    {"far"},
    {"tword"},
    {"qword"},
    {"dword"},
    {"word"},
    {"byte"},
    {NULL}};

  guint64 val = 0;
  //remove tab & newline
  buf = g_strdelimit(g_strdup(disBuf), (char *)remDel, ' ');
  g_strstrip(buf);

  iSpc = strchr(buf, 0x20); //space

  if (iSpc == NULL) {
    gs = g_string_new(buf);
  } else {
    gs = g_string_new_len(buf, iSpc - buf);
    iCom = strchr(buf, 0x2C); //comma
    if (iCom == NULL) {
      op[0] = g_new(dpfOperand, 1);
      op[0]->gs = g_string_new(iSpc + 1);
      //remove trailing newline

      iNumOps = 1;
    } else {
      op[0] = g_new(dpfOperand, 1);
      op[0]->gs = g_string_new_len(iSpc + 1, iCom - (iSpc + 1));
      op[1] = g_new(dpfOperand, 1);
      op[1]->gs = g_string_new(iCom + 1);

      iNumOps = 2;
    }
  }

  //step through the operands 
  //shouldn't be more than 2, but hey.. scalable is good
  for (int i = 0; i < iNumOps; i++) {
    //set gsType
    op[i]->gsType = g_string_new("");
    for (int j=0; ;j++) {
      if (matchType[j] == NULL)
	break;
      iType = strstr(op[i]->gs->str, matchType[j]);
      if (iType != NULL) {
	op[i]->gsType = g_string_assign(op[i]->gsType, matchType[j]);
	//remove type from operand (and trailing space)
	g_string_erase(op[i]->gs, iType - &op[i]->gs->str[0], strlen(matchType[j]) + 1);
      }
    }

    //if operand is discrete value, set iVal and truncate gs
    char *endptr = (char *)alloca(op[i]->gs->len);
    val = g_ascii_strtoull(op[i]->gs->str, &endptr, 16);
    if (*endptr == '\0') {
      op[i]->lVal = val;
      op[i]->gs = g_string_truncate(op[i]->gs, 0);
    }
  }
}

dpfInstruction::~dpfInstruction()
{
  g_string_free(gs, TRUE);
  for (int i = 0; i < iNumOps; i++) {
    g_string_free(op[i]->gs, TRUE);
    g_string_free(op[i]->gsType, TRUE);
    g_free(op[i]);
  }
  g_free(op);
}

char *dpfInstruction::getInsn()
{
  g_assert(gs != NULL);
  return gs->str;
}

guint8 dpfInstruction::numOps()
{
  return iNumOps;
}

gboolean dpfInstruction::isVal(guint8 opI)
{
  g_assert(opI <= iNumOps && opI > 0);
  g_assert(op[--opI]->gs != NULL);
  if (op[opI]->gs->len > 0)
    return false;
  else 
    return true;
}

char *dpfInstruction::getOp(guint8 opI)
{
  g_assert(op != NULL);
  g_assert(opI <= iNumOps && opI > 0);
  g_assert(op[--opI]->gs != NULL);
  if (op[opI]->gs->len > 0)
    return op[opI]->gs->str;
  else
    return "";
}

char *dpfInstruction::getType(guint8 opI)
{
  g_assert(opI <= iNumOps && opI > 0);
  g_assert(op[--opI]->gs != NULL);
  return op[opI]->gsType->str;
}

guint64 dpfInstruction::getVal(guint8 opI)
{
  g_assert(opI <= iNumOps && opI > 0);
  g_assert(op[--opI]->gs != NULL);
  return op[opI]->lVal;
}

//recombine instruction
char *dpfInstruction::getCombined()
{
  const char csComma[] = ",";
  const char csSpace[] = " ";
  char *delim = (char *)&csSpace;
  GString *gsRet = g_string_new("");
  guint8 width = 8;

  g_string_append(gsRet, gs->str);
  if (iNumOps > 0)
    g_string_append(gsRet, " ");

  for (int i = 0; i < iNumOps; i++) {
    width = 8;
    if (op[i]->gsType->len > 0)
      g_string_append_printf(gsRet, "%s ", getType(i + 1));

    if (iNumOps == 2 && i == 0)
      delim = (char *)&csComma;
    else
      delim = (char *)&csSpace;

    if (isVal(i + 1)) {
      if (!strcmp(getType(i + 1), "byte"))
	  width = 2;
      if (!strcmp(getType(i + 1), "word"))
	  width = 4;
      if (!strcmp(getType(i + 1), "dword"))
	  width = 8;

      g_string_append_printf(gsRet, "0x%0*x%s", 
			     width, getVal(i + 1), delim);
    } else {
      g_string_append_printf(gsRet, "%s%s", getOp(i + 1), delim);
    }
  }
  g_string_append_printf(gsRet, "\n");
  return gsRet->str;
}
