package com.ionspin.kotlin.bignum.decimal;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public static final b f = new b(0L, (c) null, 7);
    public final long a;
    public final c b;
    public final long c;
    public final boolean d;
    public final boolean e;

    static {
        new b(30L, c.c, 2L);
    }

    public b(long j, c roundingMode, long j2) {
        Intrinsics.checkNotNullParameter(roundingMode, "roundingMode");
        this.a = j;
        this.b = roundingMode;
        this.c = j2;
        this.d = j == 0;
        boolean z = j2 >= 0;
        this.e = z;
        c cVar = c.b;
        if (!z && j == 0 && roundingMode != cVar) {
            throw new ArithmeticException("Rounding mode with 0 digits precision.");
        }
        if (j2 < -1) {
            throw new ArithmeticException("Negative Scale is unsupported.");
        }
        if (z && roundingMode == cVar) {
            throw new ArithmeticException(d0.o(j2, "Scale of ", " digits to the right of the decimal requires a RoundingMode that is not NONE."));
        }
    }

    public static b a(b bVar, long j) {
        c roundingMode = bVar.b;
        long j2 = bVar.c;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(roundingMode, "roundingMode");
        return new b(j, roundingMode, j2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b && this.c == bVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + ((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DecimalMode(decimalPrecision=");
        sb.append(this.a);
        sb.append(", roundingMode=");
        sb.append(this.b);
        sb.append(", scale=");
        return d0.q(sb, this.c, ')');
    }

    public /* synthetic */ b(long j, c cVar, int i) {
        this((i & 1) != 0 ? 0L : j, (i & 2) != 0 ? c.b : cVar, -1L);
    }
}
