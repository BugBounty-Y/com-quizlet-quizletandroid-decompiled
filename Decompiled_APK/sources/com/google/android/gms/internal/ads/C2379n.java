package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2379n {
    public final String a;
    public final String b;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
    }

    public C2379n(String str, String str2) {
        this.a = Yo.a(str);
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2379n.class == obj.getClass()) {
            C2379n c2379n = (C2379n) obj;
            if (Objects.equals(this.a, c2379n.a) && Objects.equals(this.b, c2379n.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        String str = this.a;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }
}
