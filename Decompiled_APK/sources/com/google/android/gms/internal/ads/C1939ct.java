package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ct, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1939ct {
    public final int a;
    public final String b;

    public C1939ct(int i, String str) {
        this.a = i;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C1939ct) {
            C1939ct c1939ct = (C1939ct) obj;
            if (this.a == c1939ct.a) {
                String str = c1939ct.b;
                String str2 = this.b;
                if (str2 != null ? str2.equals(str) : str == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.b;
        return (str == null ? 0 : str.hashCode()) ^ ((this.a ^ 1000003) * 1000003);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OverlayDisplayState{statusCode=");
        sb.append(this.a);
        sb.append(", sessionToken=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
