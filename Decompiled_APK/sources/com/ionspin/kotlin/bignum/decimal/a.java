package com.ionspin.kotlin.bignum.decimal;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.ranges.l;
import kotlin.text.StringsKt;
import kotlin.v;

/* loaded from: classes2.dex */
public final class a implements com.ionspin.kotlin.bignum.a, Comparable {
    public static final a f;
    public final long a;
    public final com.ionspin.kotlin.bignum.integer.c b;
    public final long c;
    public final b d;
    public final boolean e;

    static {
        long j = 0;
        int i = 6;
        f = new a(com.ionspin.kotlin.bignum.integer.c.d, j, i);
        new a(com.ionspin.kotlin.bignum.integer.c.e, j, i);
        new a(com.ionspin.kotlin.bignum.integer.c.f, j, i);
        new a(com.ionspin.kotlin.bignum.integer.c.g, 1L, 4);
        com.quizlet.shared.usecase.folderstudymaterials.b.i(Double.MAX_VALUE);
        com.quizlet.shared.usecase.folderstudymaterials.b.i(Double.MIN_VALUE);
        com.quizlet.shared.usecase.folderstudymaterials.b.n(Float.MAX_VALUE);
        com.quizlet.shared.usecase.folderstudymaterials.b.n(Float.MIN_VALUE);
    }

    public /* synthetic */ a(com.ionspin.kotlin.bignum.integer.c cVar, long j, int i) {
        this(cVar, (i & 2) != 0 ? 0L : j, (b) null);
    }

    public static v a(a aVar, a aVar2) {
        long j = aVar.b.j();
        long j2 = aVar.c;
        com.ionspin.kotlin.bignum.integer.c cVar = aVar.b;
        int i = 4;
        a aVar3 = new a(cVar, (j2 - j) + 1, i);
        long j3 = aVar2.b.j();
        long j4 = aVar2.c;
        com.ionspin.kotlin.bignum.integer.c cVar2 = aVar2.b;
        a aVar4 = new a(cVar2, (j4 - j3) + 1, i);
        com.ionspin.kotlin.bignum.integer.c cVar3 = aVar3.b;
        com.ionspin.kotlin.bignum.integer.c cVar4 = aVar4.b;
        long j5 = aVar3.c;
        long j6 = aVar4.c;
        if (j2 > j4) {
            long j7 = j5 - j6;
            return j7 >= 0 ? new v(cVar3.o(D.c().l(j7)), cVar2, Long.valueOf(j6)) : new v(cVar, cVar4.o(D.c().l(j7 * (-1))), Long.valueOf(j5));
        }
        if (j2 < j4) {
            long j8 = j6 - j5;
            return j8 >= 0 ? new v(cVar, cVar4.o(D.c().l(j8)), Long.valueOf(j5)) : new v(cVar3.o(D.c().l(j8 * (-1))), cVar2, Long.valueOf(j5));
        }
        if (j2 != j4) {
            StringBuilder sbT = d0.t(j2, "Invalid comparison state BigInteger: ", ", ");
            sbT.append(j4);
            throw new RuntimeException(sbT.toString());
        }
        long j9 = j5 - j6;
        if (j9 > 0) {
            return new v(cVar.o(D.c().l(j9)), cVar2, Long.valueOf(j5));
        }
        if (j9 < 0) {
            return new v(cVar, cVar2.o(D.c().l(j9 * (-1))), Long.valueOf(j5));
        }
        if (Intrinsics.h(j9, 0L) == 0) {
            return new v(cVar, cVar2, Long.valueOf(j5));
        }
        throw new RuntimeException(Intrinsics.k(Long.valueOf(j9), "Invalid delta: "));
    }

    public static String d(int i, String str) {
        String str2 = StringsKt.Z(str, l.h(0, str.length() - i)) + '.' + StringsKt.Z(str, l.h(str.length() - i, str.length()));
        for (int iJ = StringsKt.J(str2); iJ >= 0; iJ--) {
            if (str2.charAt(iJ) != '0') {
                String strSubstring = str2.substring(0, iJ + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                return strSubstring;
            }
        }
        return "";
    }

    public final int b(a other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (this.c == other.c && this.a == other.a) {
            return this.b.a(other.b);
        }
        v vVarA = a(this, other);
        return ((com.ionspin.kotlin.bignum.integer.c) vVarA.a).a((com.ionspin.kotlin.bignum.integer.c) vVarA.b);
    }

    public final b c(a aVar) {
        b bVar;
        long jMax;
        b bVar2 = this.d;
        if (bVar2 == null || bVar2.d || (bVar = aVar.d) == null || bVar.d) {
            return b.f;
        }
        b bVar3 = aVar.d;
        long jMax2 = Math.max(bVar2.a, bVar3.a);
        if (bVar2.e && bVar3.e) {
            int iK = AbstractC0147y.k(1);
            long j = bVar2.c;
            long j2 = bVar3.c;
            if (iK == 0) {
                jMax = Math.max(j, j2);
            } else if (iK == 1) {
                jMax = Math.min(j, j2);
            } else {
                if (iK != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                jMax = j + j2;
            }
        } else {
            jMax = -1;
        }
        return new b(jMax2, bVar2.b, jMax);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (other instanceof Number) {
            Number number = (Number) other;
            Intrinsics.checkNotNullParameter(number, "number");
        }
        if (other instanceof a) {
            return b((a) other);
        }
        if (other instanceof Long) {
            com.ionspin.kotlin.bignum.integer.c cVar = new com.ionspin.kotlin.bignum.integer.c(((Number) other).longValue());
            return b(new a(cVar, cVar.j() - 1, (b) null));
        }
        if (other instanceof Integer) {
            return b(com.quizlet.shared.usecase.folderstudymaterials.b.o(((Number) other).intValue()));
        }
        if (other instanceof Short) {
            short sShortValue = ((Number) other).shortValue();
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarJ = com.quizlet.shared.usecase.folderstudymaterials.c.j(sShortValue);
            return b(new a(cVarJ, cVarJ.j() - 1, (b) null));
        }
        if (other instanceof Byte) {
            byte bByteValue = ((Number) other).byteValue();
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar2 = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarI = com.quizlet.shared.usecase.folderstudymaterials.c.i(bByteValue);
            return b(new a(cVarI, cVarI.j() - 1, (b) null));
        }
        if (other instanceof Double) {
            return b(com.quizlet.shared.usecase.folderstudymaterials.b.i(((Number) other).doubleValue()));
        }
        if (other instanceof Float) {
            return b(com.quizlet.shared.usecase.folderstudymaterials.b.n(((Number) other).floatValue()));
        }
        throw new RuntimeException(Intrinsics.k(K.a(other.getClass()).f(), "Invalid comparison type for BigDecimal: "));
    }

    public final a e(a other, b bVar) {
        Intrinsics.checkNotNullParameter(other, "other");
        b bVarC = com.quizlet.shared.usecase.folderstudymaterials.b.c(this.d, other.d, bVar);
        a aVar = f;
        boolean zEquals = equals(aVar);
        long j = other.c;
        if (zEquals) {
            return com.quizlet.shared.usecase.folderstudymaterials.b.f(other.b.i(), j, bVarC);
        }
        boolean zEquals2 = other.equals(aVar);
        long j2 = this.c;
        if (zEquals2) {
            return com.quizlet.shared.usecase.folderstudymaterials.b.f(this.b, j2, bVarC);
        }
        v vVarA = a(this, other);
        com.ionspin.kotlin.bignum.integer.c cVar = (com.ionspin.kotlin.bignum.integer.c) vVarA.a;
        com.ionspin.kotlin.bignum.integer.c cVar2 = (com.ionspin.kotlin.bignum.integer.c) vVarA.b;
        long j3 = cVar.j();
        long j4 = cVar2.j();
        com.ionspin.kotlin.bignum.integer.c cVarG = cVar.g(cVar2);
        long j5 = cVarG.j();
        if (j3 <= j4) {
            j3 = j4;
        }
        long jMax = Math.max(j2, j) + (j5 - j3);
        return this.e ? com.quizlet.shared.usecase.folderstudymaterials.b.f(cVarG, jMax, b.a(bVarC, j5)) : com.quizlet.shared.usecase.folderstudymaterials.b.f(cVarG, jMax, bVarC);
    }

    public final boolean equals(Object obj) {
        int iB;
        if (obj instanceof a) {
            iB = b((a) obj);
        } else if (obj instanceof Long) {
            com.ionspin.kotlin.bignum.integer.c cVar = new com.ionspin.kotlin.bignum.integer.c(((Number) obj).longValue());
            iB = b(new a(cVar, cVar.j() - 1, (b) null));
        } else if (obj instanceof Integer) {
            iB = b(com.quizlet.shared.usecase.folderstudymaterials.b.o(((Number) obj).intValue()));
        } else if (obj instanceof Short) {
            short sShortValue = ((Number) obj).shortValue();
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarJ = com.quizlet.shared.usecase.folderstudymaterials.c.j(sShortValue);
            iB = b(new a(cVarJ, cVarJ.j() - 1, (b) null));
        } else if (obj instanceof Byte) {
            byte bByteValue = ((Number) obj).byteValue();
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar2 = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarI = com.quizlet.shared.usecase.folderstudymaterials.c.i(bByteValue);
            iB = b(new a(cVarI, cVarI.j() - 1, (b) null));
        } else {
            iB = obj instanceof Double ? b(com.quizlet.shared.usecase.folderstudymaterials.b.i(((Number) obj).doubleValue())) : obj instanceof Float ? b(com.quizlet.shared.usecase.folderstudymaterials.b.n(((Number) obj).floatValue())) : -1;
        }
        return iB == 0;
    }

    public final com.ionspin.kotlin.bignum.integer.c f() {
        long j = this.c;
        if (j < 0) {
            return com.ionspin.kotlin.bignum.integer.c.d;
        }
        long j2 = j - this.a;
        com.ionspin.kotlin.bignum.integer.c cVar = this.b;
        return j2 > 0 ? cVar.o(D.c().l(j2 + 1)) : j2 < 0 ? cVar.b(D.c().l(Math.abs(j2) - 1)) : cVar;
    }

    public final int hashCode() {
        com.ionspin.kotlin.bignum.integer.c cVar;
        com.ionspin.kotlin.bignum.integer.c cVar2;
        a aVar;
        a aVar2 = f;
        if (equals(aVar2)) {
            return 0;
        }
        boolean zEquals = equals(aVar2);
        long j = this.c;
        if (zEquals) {
            aVar = this;
        } else {
            com.ionspin.kotlin.bignum.integer.c cVar3 = com.ionspin.kotlin.bignum.integer.c.d;
            com.ionspin.kotlin.bignum.integer.c cVar4 = this.b;
            com.ionspin.kotlin.bignum.integer.a aVar3 = new com.ionspin.kotlin.bignum.integer.a(cVar4, cVar3);
            do {
                aVar3 = aVar3.a.d(com.ionspin.kotlin.bignum.integer.c.g);
                cVar = com.ionspin.kotlin.bignum.integer.c.d;
                cVar2 = aVar3.b;
                if (Intrinsics.b(cVar2, cVar)) {
                    cVar4 = aVar3.a;
                }
            } while (Intrinsics.b(cVar2, cVar));
            aVar = new a(cVar4, j, 4);
        }
        return Long.hashCode(j) + aVar.b.hashCode();
    }

    public final String toString() {
        String strSubstring;
        com.ionspin.kotlin.bignum.integer.c cVar = this.b;
        String strP = cVar.p();
        int i = cVar.compareTo(0) < 0 ? 2 : 1;
        String strP2 = cVar.p();
        int iJ = StringsKt.J(strP2);
        while (true) {
            if (iJ < 0) {
                strSubstring = "";
                break;
            }
            if (strP2.charAt(iJ) != '0') {
                strSubstring = strP2.substring(0, iJ + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                break;
            }
            iJ--;
        }
        String str = strSubstring.length() <= 1 ? "0" : "";
        long j = this.c;
        if (j > 0) {
            return d(strP.length() - i, strP) + str + "E+" + j;
        }
        if (j >= 0) {
            if (j == 0) {
                return Intrinsics.k(str, d(strP.length() - i, strP));
            }
            throw new RuntimeException("Invalid state, please report a bug (Integer compareTo invalid)");
        }
        return d(strP.length() - i, strP) + str + 'E' + j;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0105  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public a(com.ionspin.kotlin.bignum.integer.c r22, long r23, com.ionspin.kotlin.bignum.decimal.b r25) {
        /*
            Method dump skipped, instructions count: 323
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.decimal.a.<init>(com.ionspin.kotlin.bignum.integer.c, long, com.ionspin.kotlin.bignum.decimal.b):void");
    }
}
