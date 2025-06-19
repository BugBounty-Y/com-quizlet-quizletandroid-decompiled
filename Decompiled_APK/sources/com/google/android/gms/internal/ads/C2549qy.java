package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.qy, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2549qy {
    public final Class a;
    public final C2604sA b;

    public /* synthetic */ C2549qy(Class cls, C2604sA c2604sA) {
        this.a = cls;
        this.b = c2604sA;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2549qy)) {
            return false;
        }
        C2549qy c2549qy = (C2549qy) obj;
        return c2549qy.a.equals(this.a) && c2549qy.b.equals(this.b);
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.l(this.a.getSimpleName(), ", object identifier: ", String.valueOf(this.b));
    }
}
