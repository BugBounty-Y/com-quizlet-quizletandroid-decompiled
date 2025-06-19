package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.sD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2607sD {
    public final long a;
    public final float b;
    public final long c;

    public /* synthetic */ C2607sD(C2564rD c2564rD) {
        this.a = c2564rD.a;
        this.b = c2564rD.b;
        this.c = c2564rD.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2607sD)) {
            return false;
        }
        C2607sD c2607sD = (C2607sD) obj;
        return this.a == c2607sD.a && this.b == c2607sD.b && this.c == c2607sD.c;
    }

    public final int hashCode() {
        return Objects.hash(Long.valueOf(this.a), Float.valueOf(this.b), Long.valueOf(this.c));
    }
}
