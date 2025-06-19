package com.ionspin.kotlin.bignum.integer;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.A;
import kotlin.C;
import kotlin.D;
import kotlin.E;
import kotlin.H;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.J;
import kotlin.x;

/* loaded from: classes2.dex */
public final class c implements com.ionspin.kotlin.bignum.a, Comparable {
    public static final com.ionspin.kotlin.bignum.integer.base63.array.b c;
    public static final c d;
    public static final c e;
    public static final c f;
    public static final c g;
    public static final double h;
    public final long[] a;
    public final int b;

    static {
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = d.a;
        c = bVar;
        bVar.getClass();
        d = new c(com.ionspin.kotlin.bignum.integer.base63.array.b.b, 3);
        e = new c(com.ionspin.kotlin.bignum.integer.base63.array.b.c, 1);
        f = new c(com.ionspin.kotlin.bignum.integer.base63.array.b.d, 1);
        g = new c(com.ionspin.kotlin.bignum.integer.base63.array.b.e, 1);
        h = Math.log10(2.0d);
    }

    public c(long[] jArr, int i) {
        if (i == 3 && !e(jArr)) {
            throw new IllegalArgumentException("sign should be Sign.ZERO iff magnitude has a value of 0");
        }
        long[] jArrR = com.ionspin.kotlin.bignum.integer.base63.array.b.r(jArr);
        this.a = jArrR;
        this.b = e(jArrR) ? 3 : i;
    }

    public static boolean e(long[] jArr) {
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        bVar.getClass();
        return bVar.e(jArr, com.ionspin.kotlin.bignum.integer.base63.array.b.b) == 0;
    }

    public final int a(c other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (f() && other.f()) {
            return 0;
        }
        boolean zF = other.f();
        int i = this.b;
        if (!zF || i != 1) {
            if (!other.f() || i != 2) {
                boolean zF2 = f();
                int i2 = other.b;
                if (!zF2 || i2 != 1) {
                    if (!f() || i2 != 2) {
                        if (i == i2) {
                            int iE = c.e(this.a, other.a);
                            return (i == 2 && i2 == 2) ? iE * (-1) : iE;
                        }
                        if (i == 1) {
                        }
                    }
                }
            }
            return -1;
        }
        return 1;
    }

    public final c b(c other) {
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(other, "other");
        return (c) c(other);
    }

    public final com.ionspin.kotlin.bignum.a c(com.ionspin.kotlin.bignum.a aVar) {
        c other = (c) aVar;
        Intrinsics.checkNotNullParameter(other, "other");
        if (other.f()) {
            throw new ArithmeticException("Division by zero! " + this + " / " + other);
        }
        long[] jArr = this.a;
        long[] jArr2 = other.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        long[] jArr3 = ((E) bVar.i(jArr, jArr2).a).a;
        bVar.getClass();
        if (Intrinsics.b(jArr3, com.ionspin.kotlin.bignum.integer.base63.array.b.b)) {
            return d;
        }
        return new c(jArr3, this.b != other.b ? 2 : 1);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (other instanceof Number) {
            Number number = (Number) other;
            Intrinsics.checkNotNullParameter(number, "number");
        }
        if (other instanceof c) {
            return a((c) other);
        }
        if (other instanceof Long) {
            return a(new c(((Number) other).longValue()));
        }
        if (other instanceof Integer) {
            return a(new c(((Number) other).intValue()));
        }
        if (other instanceof Short) {
            return a(com.quizlet.shared.usecase.folderstudymaterials.c.j(((Number) other).shortValue()));
        }
        if (other instanceof Byte) {
            return a(com.quizlet.shared.usecase.folderstudymaterials.c.i(((Number) other).byteValue()));
        }
        if (other instanceof D) {
            return a(com.quizlet.shared.usecase.folderstudymaterials.c.n(((D) other).a));
        }
        boolean z = other instanceof A;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        if (z) {
            int i = ((A) other).a;
            bVar.getClass();
            long j = i & 4294967295L;
            C c2 = D.b;
            return a(new c(new long[]{j}, 1));
        }
        if (other instanceof H) {
            short s = ((H) other).a;
            bVar.getClass();
            long j2 = s & 65535;
            C c3 = D.b;
            return a(new c(new long[]{j2}, 1));
        }
        if (other instanceof x) {
            byte b = ((x) other).a;
            bVar.getClass();
            long j3 = b & 255;
            C c4 = D.b;
            return a(new c(new long[]{j3}, 1));
        }
        if (other instanceof Float) {
            float fFloatValue = ((Number) other).floatValue();
            b comparisonBlock = new b(this, 0);
            Intrinsics.checkNotNullParameter(comparisonBlock, "comparisonBlock");
            float fFloor = (float) Math.floor(fFloatValue);
            float f2 = 1;
            if (fFloatValue % f2 == DefinitionKt.NO_Float_VALUE) {
                double d2 = fFloor;
                Math.floor(d2);
                com.ionspin.kotlin.bignum.decimal.a aVar = com.ionspin.kotlin.bignum.decimal.a.f;
                return ((Number) comparisonBlock.invoke(com.quizlet.shared.usecase.folderstudymaterials.b.n((float) Math.floor(d2)).f())).intValue();
            }
            double d3 = fFloor + f2;
            Math.floor(d3);
            com.ionspin.kotlin.bignum.decimal.a aVar2 = com.ionspin.kotlin.bignum.decimal.a.f;
            int iIntValue = ((Number) comparisonBlock.invoke(com.quizlet.shared.usecase.folderstudymaterials.b.n((float) Math.floor(d3)).f())).intValue();
            if (iIntValue == 0) {
                return 1;
            }
            return iIntValue;
        }
        if (!(other instanceof Double)) {
            throw new RuntimeException(Intrinsics.k(K.a(other.getClass()), "Invalid comparison type for BigInteger: "));
        }
        double dDoubleValue = ((Number) other).doubleValue();
        b comparisonBlock2 = new b(this, 1);
        Intrinsics.checkNotNullParameter(comparisonBlock2, "comparisonBlock");
        double dFloor = Math.floor(dDoubleValue);
        double d4 = 1;
        if (dDoubleValue % d4 == 0.0d) {
            Math.floor(dFloor);
            com.ionspin.kotlin.bignum.decimal.a aVar3 = com.ionspin.kotlin.bignum.decimal.a.f;
            return ((Number) comparisonBlock2.invoke(com.quizlet.shared.usecase.folderstudymaterials.b.i(Math.floor(dFloor)).f())).intValue();
        }
        double d5 = dFloor + d4;
        Math.floor(d5);
        com.ionspin.kotlin.bignum.decimal.a aVar4 = com.ionspin.kotlin.bignum.decimal.a.f;
        int iIntValue2 = ((Number) comparisonBlock2.invoke(com.quizlet.shared.usecase.folderstudymaterials.b.i(Math.floor(d5)).f())).intValue();
        if (iIntValue2 == 0) {
            return 1;
        }
        return iIntValue2;
    }

    public final a d(c other) {
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(other, "other");
        if (other.f()) {
            throw new ArithmeticException("Division by zero! " + this + " / " + other);
        }
        int i = other.b;
        int i2 = this.b;
        int i3 = i2 != i ? 2 : 1;
        long[] jArr = this.a;
        long[] jArr2 = other.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        Pair pairI = bVar.i(jArr, jArr2);
        E e2 = (E) pairI.a;
        long[] jArr3 = e2.a;
        bVar.getClass();
        long[] jArr4 = com.ionspin.kotlin.bignum.integer.base63.array.b.b;
        boolean zB = Intrinsics.b(jArr3, jArr4);
        c cVar = d;
        c cVar2 = zB ? cVar : new c(e2.a, i3);
        E e3 = (E) pairI.b;
        if (!Intrinsics.b(e3.a, jArr4)) {
            cVar = new c(e3.a, i2);
        }
        return new a(cVar2, cVar);
    }

    public final boolean equals(Object obj) {
        int iA;
        if (obj instanceof c) {
            iA = a((c) obj);
        } else if (obj instanceof Long) {
            iA = a(new c(((Number) obj).longValue()));
        } else if (obj instanceof Integer) {
            iA = a(new c(((Number) obj).intValue()));
        } else if (obj instanceof Short) {
            iA = a(com.quizlet.shared.usecase.folderstudymaterials.c.j(((Number) obj).shortValue()));
        } else if (obj instanceof Byte) {
            iA = a(com.quizlet.shared.usecase.folderstudymaterials.c.i(((Number) obj).byteValue()));
        } else if (obj instanceof D) {
            iA = a(com.quizlet.shared.usecase.folderstudymaterials.c.n(((D) obj).a));
        } else {
            boolean z = obj instanceof A;
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
            if (z) {
                int i = ((A) obj).a;
                bVar.getClass();
                long j = i & 4294967295L;
                C c2 = D.b;
                iA = a(new c(new long[]{j}, 1));
            } else if (obj instanceof H) {
                short s = ((H) obj).a;
                bVar.getClass();
                long j2 = s & 65535;
                C c3 = D.b;
                iA = a(new c(new long[]{j2}, 1));
            } else if (obj instanceof x) {
                byte b = ((x) obj).a;
                bVar.getClass();
                long j3 = b & 255;
                C c4 = D.b;
                iA = a(new c(new long[]{j3}, 1));
            } else {
                iA = -1;
            }
        }
        return iA == 0;
    }

    public final boolean f() {
        if (this.b == 3) {
            return true;
        }
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = d.a;
        bVar.getClass();
        return bVar.e(this.a, com.ionspin.kotlin.bignum.integer.base63.array.b.b) == 0;
    }

    public final c g(c other) {
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(other, "other");
        long[] jArr = other.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        long[] jArr2 = this.a;
        int iE = bVar.e(jArr2, jArr);
        c cVar = d;
        if (equals(cVar)) {
            return other.i();
        }
        if (other.equals(cVar)) {
            return this;
        }
        int i = other.b;
        int i2 = this.b;
        long[] jArr3 = other.a;
        if (i != i2) {
            return new c(bVar.a(jArr2, jArr3), i2);
        }
        if (iE > 0) {
            return new c(bVar.w(jArr2, jArr3), i2);
        }
        if (iE >= 0) {
            return cVar;
        }
        long[] jArrW = bVar.w(jArr3, jArr2);
        int iK = AbstractC0147y.k(i2);
        int i3 = 2;
        if (iK != 0) {
            if (iK == 1) {
                i3 = 1;
            } else {
                if (iK != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i3 = 3;
            }
        }
        return new c(jArrW, i3);
    }

    public final c h(c other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (f() || other.f()) {
            return d;
        }
        if (other.equals(e)) {
            return this;
        }
        int i = this.b != other.b ? 2 : 1;
        long[] jArr = this.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        long[] jArr2 = other.a;
        return i == 1 ? new c(bVar.n(jArr, jArr2), i) : new c(bVar.n(jArr, jArr2), i);
    }

    public final int hashCode() {
        int iHashCode = 0;
        for (long j : this.a) {
            C c2 = D.b;
            iHashCode += Long.hashCode(j);
        }
        return AbstractC0147y.k(this.b) + iHashCode;
    }

    public final c i() {
        int iK = AbstractC0147y.k(this.b);
        int i = 2;
        if (iK != 0) {
            if (iK == 1) {
                i = 1;
            } else {
                if (iK != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i = 3;
            }
        }
        return new c(this.a, i);
    }

    public final long j() {
        if (f()) {
            return 1L;
        }
        long jCeil = (int) Math.ceil((c.d(this.a) - 1) * h);
        c cVarB = b(com.google.android.gms.internal.mlkit_vision_document_scanner.D.c().l(jCeil));
        long j = 0;
        while (cVarB.compareTo(0) != 0) {
            Intrinsics.checkNotNullParameter(cVarB, "this");
            cVarB = (c) cVarB.c(new c(10));
            j++;
        }
        return j + jCeil;
    }

    public final c k(com.ionspin.kotlin.bignum.a aVar) {
        c other = (c) aVar;
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(other, "other");
        long[] jArr = other.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        long[] jArr2 = this.a;
        int iE = bVar.e(jArr2, jArr);
        int i = this.b;
        int i2 = other.b;
        long[] jArr3 = other.a;
        return i2 == i ? new c(bVar.a(jArr2, jArr3), i) : iE > 0 ? new c(bVar.w(jArr2, jArr3), i) : iE < 0 ? new c(bVar.w(jArr3, jArr2), i2) : d;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0064  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.ionspin.kotlin.bignum.integer.c l(long r20) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            r3 = 0
            int r5 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r5 < 0) goto L8c
            com.ionspin.kotlin.bignum.integer.c r6 = com.ionspin.kotlin.bignum.integer.c.d
            boolean r7 = r0.equals(r6)
            if (r7 == 0) goto L13
            return r6
        L13:
            com.ionspin.kotlin.bignum.integer.c r6 = com.ionspin.kotlin.bignum.integer.c.e
            boolean r7 = r0.equals(r6)
            if (r7 == 0) goto L1c
            return r6
        L1c:
            int r6 = r0.b
            r7 = 1
            r8 = 2
            if (r6 != r8) goto L29
            long r9 = (long) r8
            long r9 = r1 % r9
            int r6 = (r9 > r3 ? 1 : (r9 == r3 ? 0 : -1))
            if (r6 != 0) goto L2b
        L29:
            r6 = r7
            goto L2c
        L2b:
            r6 = r8
        L2c:
            com.ionspin.kotlin.bignum.integer.c r9 = new com.ionspin.kotlin.bignum.integer.c
            com.ionspin.kotlin.bignum.integer.base63.array.b r10 = com.ionspin.kotlin.bignum.integer.c.c
            r10.getClass()
            long[] r11 = r0.a
            java.lang.String r12 = "base"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r12)
            long[] r12 = com.ionspin.kotlin.bignum.integer.base63.array.b.c
            if (r5 != 0) goto L40
            r11 = r12
            goto L88
        L40:
            r13 = 1
            int r5 = (r1 > r13 ? 1 : (r1 == r13 ? 0 : -1))
            if (r5 != 0) goto L47
            goto L88
        L47:
            int r5 = r11.length
            if (r5 != r7) goto L64
            r5 = 0
            r15 = r11[r5]
            kotlin.C r5 = kotlin.D.b
            r17 = 10
            int r5 = (r15 > r17 ? 1 : (r15 == r17 ? 0 : -1))
            if (r5 != 0) goto L64
            kotlin.E[] r5 = com.ionspin.kotlin.bignum.integer.base63.array.b.g
            int r7 = r5.length
            r15 = r3
            long r3 = (long) r7
            int r3 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r3 >= 0) goto L65
            int r1 = (int) r1
            r1 = r5[r1]
            long[] r11 = r1.a
            goto L88
        L64:
            r15 = r3
        L65:
            com.ionspin.kotlin.bignum.integer.base63.array.b.h(r11)
        L68:
            int r3 = (r1 > r13 ? 1 : (r1 == r13 ? 0 : -1))
            if (r3 <= 0) goto L84
            long r3 = (long) r8
            long r17 = r1 % r3
            int r5 = (r17 > r15 ? 1 : (r17 == r15 ? 0 : -1))
            if (r5 != 0) goto L79
            long[] r11 = r10.y(r11, r11)
            long r1 = r1 / r3
            goto L68
        L79:
            long[] r12 = r10.y(r11, r12)
            long[] r11 = r10.y(r11, r11)
            long r1 = r1 - r13
            long r1 = r1 / r3
            goto L68
        L84:
            long[] r11 = r10.y(r12, r11)
        L88:
            r9.<init>(r11, r6)
            return r9
        L8c:
            java.lang.ArithmeticException r1 = new java.lang.ArithmeticException
            java.lang.String r2 = "Negative exponent not supported with BigInteger"
            r1.<init>(r2)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.c.l(long):com.ionspin.kotlin.bignum.integer.c");
    }

    public final c m(c other) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (other.f()) {
            throw new ArithmeticException("Division by zero! " + this + " / " + other);
        }
        int i = this.b != other.b ? 2 : 1;
        long[] jArr = this.a;
        long[] jArr2 = other.a;
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        long[] jArr3 = ((E) bVar.i(jArr, jArr2).b).a;
        bVar.getClass();
        if (Intrinsics.b(jArr3, com.ionspin.kotlin.bignum.integer.base63.array.b.b)) {
            i = 3;
        }
        return new c(jArr3, i);
    }

    public final int n() {
        int iK = AbstractC0147y.k(this.b);
        if (iK == 0) {
            return 1;
        }
        if (iK == 1) {
            return -1;
        }
        if (iK == 2) {
            return 0;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final c o(com.ionspin.kotlin.bignum.a aVar) {
        c other = (c) aVar;
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(other, "other");
        return h(other);
    }

    public final String p() {
        String str = this.b == 2 ? "-" : "";
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = c;
        bVar.getClass();
        long[] operand = this.a;
        Intrinsics.checkNotNullParameter(operand, "operand");
        long[] receiver = Arrays.copyOf(operand, operand.length);
        Intrinsics.checkNotNullExpressionValue(receiver, "java.util.Arrays.copyOf(this, size)");
        Intrinsics.checkNotNullParameter(receiver, "storage");
        C c2 = D.b;
        long[] other = {10};
        StringBuilder sb = new StringBuilder();
        while (!Intrinsics.b(receiver, com.ionspin.kotlin.bignum.integer.base63.array.b.b)) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(other, "other");
            Pair pairI = bVar.i(receiver, other);
            long[] jArr = ((E) pairI.b).a;
            if (jArr.length == 0) {
                sb.append(0);
            } else {
                long j = jArr[0];
                C c3 = D.b;
                sb.append(J.b(j));
            }
            receiver = ((E) pairI.a).a;
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "stringBuilder.toString()");
        Intrinsics.checkNotNullParameter(string, "<this>");
        StringBuilder sbReverse = new StringBuilder((CharSequence) string).reverse();
        Intrinsics.checkNotNullExpressionValue(sbReverse, "reverse(...)");
        return Intrinsics.k(sbReverse.toString(), str);
    }

    public final String toString() {
        return p();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0046  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(long r11) {
        /*
            r10 = this;
            r0 = 1
            r1 = 2
            com.ionspin.kotlin.bignum.integer.base63.array.b r2 = com.ionspin.kotlin.bignum.integer.c.c
            r2.getClass()
            r2 = -9223372036854775808
            int r2 = (r11 > r2 ? 1 : (r11 == r2 ? 0 : -1))
            r3 = 0
            if (r2 != 0) goto L15
            long[] r2 = new long[r1]
            r2 = {x00b2: FILL_ARRAY_DATA , data: [0, 1} // fill-array
            goto L26
        L15:
            long r5 = java.lang.Math.abs(r11)
            kotlin.C r2 = kotlin.D.b
            r7 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            long r5 = r5 & r7
            long[] r2 = new long[r0]
            r7 = 0
            r2[r7] = r5
        L26:
            java.lang.Long r5 = java.lang.Long.valueOf(r11)
            java.lang.Class<java.lang.Long> r6 = java.lang.Long.class
            kotlin.jvm.internal.i r7 = kotlin.jvm.internal.K.a(r6)
            java.lang.Class r8 = java.lang.Long.TYPE
            kotlin.jvm.internal.i r8 = kotlin.jvm.internal.K.a(r8)
            boolean r8 = r7.equals(r8)
            r9 = 3
            if (r8 == 0) goto L48
            int r11 = (r11 > r3 ? 1 : (r11 == r3 ? 0 : -1))
            if (r11 >= 0) goto L43
        L41:
            r0 = r1
            goto L9e
        L43:
            if (r11 <= 0) goto L46
            goto L9e
        L46:
            r0 = r9
            goto L9e
        L48:
            java.lang.Class r11 = java.lang.Integer.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r7.equals(r11)
            if (r11 == 0) goto L65
            r11 = r5
            java.lang.Integer r11 = (java.lang.Integer) r11
            int r11 = r5.intValue()
            if (r11 >= 0) goto L5e
            goto L41
        L5e:
            int r11 = r5.intValue()
            if (r11 <= 0) goto L46
            goto L9e
        L65:
            java.lang.Class r11 = java.lang.Short.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r7.equals(r11)
            if (r11 == 0) goto L82
            r11 = r5
            java.lang.Short r11 = (java.lang.Short) r11
            short r11 = r5.shortValue()
            if (r11 >= 0) goto L7b
            goto L41
        L7b:
            short r11 = r5.shortValue()
            if (r11 <= 0) goto L46
            goto L9e
        L82:
            java.lang.Class r11 = java.lang.Byte.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r7.equals(r11)
            if (r11 == 0) goto La2
            r11 = r5
            java.lang.Byte r11 = (java.lang.Byte) r11
            byte r11 = r5.byteValue()
            if (r11 >= 0) goto L98
            goto L41
        L98:
            byte r11 = r5.byteValue()
            if (r11 <= 0) goto L46
        L9e:
            r10.<init>(r2, r0)
            return
        La2:
            java.lang.RuntimeException r11 = new java.lang.RuntimeException
            kotlin.jvm.internal.i r12 = kotlin.jvm.internal.K.a(r6)
            java.lang.String r0 = "Unsupported type "
            java.lang.String r12 = kotlin.jvm.internal.Intrinsics.k(r12, r0)
            r11.<init>(r12)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.c.<init>(long):void");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0037  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(int r11) {
        /*
            r10 = this;
            r0 = 1
            com.ionspin.kotlin.bignum.integer.base63.array.b r1 = com.ionspin.kotlin.bignum.integer.c.c
            r1.getClass()
            long r1 = (long) r11
            long r1 = java.lang.Math.abs(r1)
            kotlin.C r3 = kotlin.D.b
            long[] r3 = new long[r0]
            r4 = 0
            r3[r4] = r1
            java.lang.Integer r1 = java.lang.Integer.valueOf(r11)
            java.lang.Class<java.lang.Integer> r2 = java.lang.Integer.class
            kotlin.jvm.internal.i r4 = kotlin.jvm.internal.K.a(r2)
            java.lang.Class r5 = java.lang.Long.TYPE
            kotlin.jvm.internal.i r5 = kotlin.jvm.internal.K.a(r5)
            boolean r5 = r4.equals(r5)
            r6 = 3
            r7 = 2
            if (r5 == 0) goto L44
            r11 = r1
            java.lang.Long r11 = (java.lang.Long) r11
            long r4 = r1.longValue()
            r8 = 0
            int r11 = (r4 > r8 ? 1 : (r4 == r8 ? 0 : -1))
            if (r11 >= 0) goto L39
        L37:
            r0 = r7
            goto L8f
        L39:
            long r1 = r1.longValue()
            int r11 = (r1 > r8 ? 1 : (r1 == r8 ? 0 : -1))
            if (r11 <= 0) goto L42
            goto L8f
        L42:
            r0 = r6
            goto L8f
        L44:
            java.lang.Class r5 = java.lang.Integer.TYPE
            kotlin.jvm.internal.i r5 = kotlin.jvm.internal.K.a(r5)
            boolean r5 = r4.equals(r5)
            if (r5 == 0) goto L56
            if (r11 >= 0) goto L53
            goto L37
        L53:
            if (r11 <= 0) goto L42
            goto L8f
        L56:
            java.lang.Class r11 = java.lang.Short.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r4.equals(r11)
            if (r11 == 0) goto L73
            r11 = r1
            java.lang.Short r11 = (java.lang.Short) r11
            short r11 = r1.shortValue()
            if (r11 >= 0) goto L6c
            goto L37
        L6c:
            short r11 = r1.shortValue()
            if (r11 <= 0) goto L42
            goto L8f
        L73:
            java.lang.Class r11 = java.lang.Byte.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r4.equals(r11)
            if (r11 == 0) goto L93
            r11 = r1
            java.lang.Byte r11 = (java.lang.Byte) r11
            byte r11 = r1.byteValue()
            if (r11 >= 0) goto L89
            goto L37
        L89:
            byte r11 = r1.byteValue()
            if (r11 <= 0) goto L42
        L8f:
            r10.<init>(r3, r0)
            return
        L93:
            java.lang.RuntimeException r11 = new java.lang.RuntimeException
            kotlin.jvm.internal.i r0 = kotlin.jvm.internal.K.a(r2)
            java.lang.String r1 = "Unsupported type "
            java.lang.String r0 = kotlin.jvm.internal.Intrinsics.k(r0, r1)
            r11.<init>(r0)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.c.<init>(int):void");
    }
}
