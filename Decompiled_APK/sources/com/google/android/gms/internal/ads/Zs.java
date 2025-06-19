package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Zs {
    public final String a;
    public final String b;

    public Zs(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Zs) {
            Zs zs = (Zs) obj;
            String str = this.a;
            if (str != null ? str.equals(zs.a) : zs.a == null) {
                String str2 = this.b;
                if (str2 != null ? str2.equals(zs.b) : zs.b == null) {
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
        StringBuilder sb = new StringBuilder("OverlayDisplayDismissRequest{sessionToken=");
        sb.append(this.a);
        sb.append(", appId=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
