package androidx.collection;

import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: androidx.collection.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0226y {
    public long[] a;
    public int b;

    public C0226y(int i) {
        this.a = i == 0 ? AbstractC0218p.a : new long[i];
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0226y) {
            C0226y c0226y = (C0226y) obj;
            int i = c0226y.b;
            int i2 = this.b;
            if (i == i2) {
                long[] jArr = this.a;
                long[] jArr2 = c0226y.a;
                IntRange intRangeH = kotlin.ranges.l.h(0, i2);
                int i3 = intRangeH.a;
                int i4 = intRangeH.b;
                if (i3 > i4) {
                    return true;
                }
                while (jArr[i3] == jArr2[i3]) {
                    if (i3 == i4) {
                        return true;
                    }
                    i3++;
                }
                return false;
            }
        }
        return false;
    }

    public final int hashCode() {
        long[] jArr = this.a;
        int i = this.b;
        int iHashCode = 0;
        for (int i2 = 0; i2 < i; i2++) {
            iHashCode += Long.hashCode(jArr[i2]) * 31;
        }
        return iHashCode;
    }

    public final String toString() {
        Intrinsics.checkNotNullParameter(", ", "separator");
        Intrinsics.checkNotNullParameter("[", "prefix");
        Intrinsics.checkNotNullParameter("]", "postfix");
        Intrinsics.checkNotNullParameter("...", "truncated");
        StringBuilder sb = new StringBuilder();
        sb.append((CharSequence) "[");
        long[] jArr = this.a;
        int i = this.b;
        int i2 = 0;
        while (true) {
            if (i2 >= i) {
                sb.append((CharSequence) "]");
                break;
            }
            long j = jArr[i2];
            if (i2 == -1) {
                sb.append((CharSequence) "...");
                break;
            }
            if (i2 != 0) {
                sb.append((CharSequence) ", ");
            }
            sb.append(j);
            i2++;
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
