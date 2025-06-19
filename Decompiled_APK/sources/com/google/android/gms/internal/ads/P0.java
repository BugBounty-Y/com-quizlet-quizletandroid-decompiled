package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class P0 extends W0 {
    public final String b;
    public final String c;
    public final int d;
    public final byte[] e;

    public P0(String str, String str2, int i, byte[] bArr) {
        super("APIC");
        this.b = str;
        this.c = str2;
        this.d = i;
        this.e = bArr;
    }

    @Override // com.google.android.gms.internal.ads.W0, com.google.android.gms.internal.ads.InterfaceC2856y4
    public final void a(L3 l3) {
        l3.a(this.d, this.e);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && P0.class == obj.getClass()) {
            P0 p0 = (P0) obj;
            if (this.d == p0.d && Objects.equals(this.b, p0.b) && Objects.equals(this.c, p0.c) && Arrays.equals(this.e, p0.e)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.b;
        int iHashCode = str != null ? str.hashCode() : 0;
        String str2 = this.c;
        return Arrays.hashCode(this.e) + ((((((this.d + 527) * 31) + iHashCode) * 31) + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.gms.internal.ads.W0
    public final String toString() {
        return this.a + ": mimeType=" + this.b + ", description=" + this.c;
    }
}
