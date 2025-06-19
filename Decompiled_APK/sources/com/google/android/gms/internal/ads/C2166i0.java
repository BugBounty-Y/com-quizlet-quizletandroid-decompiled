package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.i0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2166i0 {
    public static final C2166i0 c = new C2166i0(0, 0);
    public final long a;
    public final long b;

    public C2166i0(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2166i0.class == obj.getClass()) {
            C2166i0 c2166i0 = (C2166i0) obj;
            if (this.a == c2166i0.a && this.b == c2166i0.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (((int) this.a) * 31) + ((int) this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("[timeUs=");
        sb.append(this.a);
        sb.append(", position=");
        return android.support.v4.media.session.a.g(this.b, "]", sb);
    }
}
