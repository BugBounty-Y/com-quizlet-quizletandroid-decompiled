package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.gq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2111gq implements InterfaceC2856y4 {
    public final float a;
    public final float b;

    public C2111gq(float f, float f2) {
        boolean z = false;
        if (f >= -90.0f && f <= 90.0f && f2 >= -180.0f && f2 <= 180.0f) {
            z = true;
        }
        AbstractC1795We.G(z, "Invalid latitude or longitude");
        this.a = f;
        this.b = f2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2111gq.class == obj.getClass()) {
            C2111gq c2111gq = (C2111gq) obj;
            if (this.a == c2111gq.a && this.b == c2111gq.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Float.floatToIntBits(this.b) + ((Float.floatToIntBits(this.a) + 527) * 31);
    }

    public final String toString() {
        return "xyz: latitude=" + this.a + ", longitude=" + this.b;
    }
}
