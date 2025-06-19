package com.ionspin.kotlin.bignum.integer.base63.array;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final long[] a;
    public final boolean b;

    public a(long[] jArr, boolean z) {
        this.a = jArr;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int hashCode() {
        int iHashCode = Arrays.hashCode(this.a) * 31;
        boolean z = this.b;
        int i = z;
        if (z != 0) {
            i = 1;
        }
        return iHashCode + i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SignedULongArray(unsignedValue=");
        sb.append((Object) ("ULongArray(storage=" + Arrays.toString(this.a) + ')'));
        sb.append(", sign=");
        return android.support.v4.media.session.a.u(sb, this.b, ')');
    }
}
