package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.g1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2079g1 implements InterfaceC2856y4 {
    public final float a;
    public final int b;

    public C2079g1(float f, int i) {
        this.a = f;
        this.b = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2079g1.class == obj.getClass()) {
            C2079g1 c2079g1 = (C2079g1) obj;
            if (this.a == c2079g1.a && this.b == c2079g1.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((Float.floatToIntBits(this.a) + 527) * 31) + this.b;
    }

    public final String toString() {
        return "smta: captureFrameRate=" + this.a + ", svcTemporalLayerCount=" + this.b;
    }
}
