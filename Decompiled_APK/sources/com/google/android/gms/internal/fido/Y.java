package com.google.android.gms.internal.fido;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class Y extends b0 {
    public final long a;

    public Y(long j) {
        this.a = j;
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d(this.a >= 0 ? (byte) 0 : (byte) 32);
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Object obj) {
        b0 b0Var = (b0) obj;
        if (a() != b0Var.a()) {
            return a() - b0Var.a();
        }
        long jAbs = Math.abs(this.a);
        long jAbs2 = Math.abs(((Y) b0Var).a);
        if (jAbs < jAbs2) {
            return -1;
        }
        return jAbs > jAbs2 ? 1 : 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && Y.class == obj.getClass() && this.a == ((Y) obj).a;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(a()), Long.valueOf(this.a)});
    }

    public final String toString() {
        return Long.toString(this.a);
    }
}
