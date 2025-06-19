package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class IF {
    public final long a;
    public final long b;

    public IF(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof IF)) {
            return false;
        }
        IF r8 = (IF) obj;
        return this.a == r8.a && this.b == r8.b;
    }

    public final int hashCode() {
        return (((int) this.a) * 31) + ((int) this.b);
    }
}
