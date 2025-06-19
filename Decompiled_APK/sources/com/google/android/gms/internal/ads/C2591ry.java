package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.ry, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2591ry {
    public final Class a;
    public final Class b;

    public /* synthetic */ C2591ry(Class cls, Class cls2) {
        this.a = cls;
        this.b = cls2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2591ry)) {
            return false;
        }
        C2591ry c2591ry = (C2591ry) obj;
        return c2591ry.a.equals(this.a) && c2591ry.b.equals(this.b);
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.l(this.a.getSimpleName(), " with serialization type: ", this.b.getSimpleName());
    }
}
