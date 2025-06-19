package com.google.android.gms.internal.ads;

import com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor;

/* renamed from: com.google.android.gms.internal.ads.Nd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1740Nd {
    public static final C1740Nd d = new C1740Nd(0, 1.0f, 0);
    public final int a;
    public final int b;
    public final float c;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(3, 36);
    }

    public C1740Nd(int i, float f, int i2) {
        this.a = i;
        this.b = i2;
        this.c = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C1740Nd) {
            C1740Nd c1740Nd = (C1740Nd) obj;
            if (this.a == c1740Nd.a && this.b == c1740Nd.b && this.c == c1740Nd.c) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Float.floatToRawIntBits(this.c) + ((((this.a + ModuleDescriptor.MODULE_VERSION) * 31) + this.b) * 31);
    }
}
