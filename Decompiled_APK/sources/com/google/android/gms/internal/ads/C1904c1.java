package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.c1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1904c1 extends W0 {
    public final String b;
    public final String c;

    public C1904c1(String str, String str2, String str3) {
        super(str);
        this.b = str2;
        this.c = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1904c1.class == obj.getClass()) {
            C1904c1 c1904c1 = (C1904c1) obj;
            if (this.a.equals(c1904c1.a) && Objects.equals(this.b, c1904c1.b) && Objects.equals(this.c, c1904c1.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() + 527;
        String str = this.b;
        return this.c.hashCode() + (((iHashCode * 31) + (str != null ? str.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.gms.internal.ads.W0
    public final String toString() {
        return this.a + ": url=" + this.c;
    }
}
