package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Y0 extends W0 {
    public final String b;
    public final String c;
    public final String d;

    public Y0(String str, String str2, String str3) {
        super("----");
        this.b = str;
        this.c = str2;
        this.d = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && Y0.class == obj.getClass()) {
            Y0 y0 = (Y0) obj;
            if (Objects.equals(this.c, y0.c) && Objects.equals(this.b, y0.b) && Objects.equals(this.d, y0.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + 527) * 31)) * 31);
    }

    @Override // com.google.android.gms.internal.ads.W0
    public final String toString() {
        return this.a + ": domain=" + this.b + ", description=" + this.c;
    }
}
