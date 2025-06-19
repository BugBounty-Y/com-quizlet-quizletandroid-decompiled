package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class R5 {
    public final long a;
    public final String b;
    public final int c;

    public R5(int i, long j, String str) {
        this.a = j;
        this.b = str;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (obj != null && (obj instanceof R5)) {
            R5 r5 = (R5) obj;
            if (r5.a == this.a && r5.c == this.c) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (int) this.a;
    }
}
