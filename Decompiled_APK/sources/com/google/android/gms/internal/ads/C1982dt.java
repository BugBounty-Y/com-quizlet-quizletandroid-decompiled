package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.dt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1982dt {
    public final String a;
    public final String b;

    public C1982dt(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C1982dt) {
            C1982dt c1982dt = (C1982dt) obj;
            String str = this.a;
            if (str != null ? str.equals(c1982dt.a) : c1982dt.a == null) {
                String str2 = this.b;
                if (str2 != null ? str2.equals(c1982dt.b) : c1982dt.b == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = str == null ? 0 : str.hashCode();
        String str2 = this.b;
        return (str2 != null ? str2.hashCode() : 0) ^ ((iHashCode ^ 1000003) * 1000003);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OverlayDisplayUpdateRequest{sessionToken=");
        sb.append(this.a);
        sb.append(", appId=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
