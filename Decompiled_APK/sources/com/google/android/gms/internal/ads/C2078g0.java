package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2078g0 {
    public final C2166i0 a;
    public final C2166i0 b;

    public C2078g0(C2166i0 c2166i0, C2166i0 c2166i02) {
        this.a = c2166i0;
        this.b = c2166i02;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2078g0.class == obj.getClass()) {
            C2078g0 c2078g0 = (C2078g0) obj;
            if (this.a.equals(c2078g0.a) && this.b.equals(c2078g0.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        C2166i0 c2166i0 = this.a;
        String string = c2166i0.toString();
        C2166i0 c2166i02 = this.b;
        return android.support.v4.media.session.a.m("[", string, c2166i0.equals(c2166i02) ? "" : ", ".concat(c2166i02.toString()), "]");
    }
}
