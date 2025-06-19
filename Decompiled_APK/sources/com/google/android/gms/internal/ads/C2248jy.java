package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.jy, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2248jy {
    public final Class a;
    public final Class b;

    public /* synthetic */ C2248jy(Class cls, Class cls2) {
        this.a = cls;
        this.b = cls2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2248jy)) {
            return false;
        }
        C2248jy c2248jy = (C2248jy) obj;
        return c2248jy.a.equals(this.a) && c2248jy.b.equals(this.b);
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.l(this.a.getSimpleName(), " with primitive type: ", this.b.getSimpleName());
    }
}
