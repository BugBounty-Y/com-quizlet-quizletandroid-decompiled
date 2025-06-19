package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.gF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2093gF {
    public final Object a;
    public final int b;
    public final int c;
    public final long d;
    public final int e;

    public C2093gF(Object obj, int i, int i2, long j, int i3) {
        this.a = obj;
        this.b = i;
        this.c = i2;
        this.d = j;
        this.e = i3;
    }

    public final C2093gF a(Object obj) {
        return this.a.equals(obj) ? this : new C2093gF(obj, this.b, this.c, this.d, this.e);
    }

    public final boolean b() {
        return this.b != -1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2093gF)) {
            return false;
        }
        C2093gF c2093gF = (C2093gF) obj;
        return this.a.equals(c2093gF.a) && this.b == c2093gF.b && this.c == c2093gF.c && this.d == c2093gF.d && this.e == c2093gF.e;
    }

    public final int hashCode() {
        return ((((((((this.a.hashCode() + 527) * 31) + this.b) * 31) + this.c) * 31) + ((int) this.d)) * 31) + this.e;
    }

    public C2093gF(long j, Object obj) {
        this(obj, -1, -1, j, -1);
    }

    public C2093gF(Object obj, long j, int i) {
        this(obj, -1, -1, j, i);
    }
}
