package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class w extends J {
    public final I a;
    public final H b;

    public w(I i, H h) {
        this.a = i;
        this.b = h;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof J) {
            J j = (J) obj;
            I i = this.a;
            if (i != null ? i.equals(((w) j).a) : ((w) j).a == null) {
                H h = this.b;
                if (h != null ? h.equals(((w) j).b) : ((w) j).b == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        I i = this.a;
        int iHashCode = ((i == null ? 0 : i.hashCode()) ^ 1000003) * 1000003;
        H h = this.b;
        return (h != null ? h.hashCode() : 0) ^ iHashCode;
    }

    public final String toString() {
        return "NetworkConnectionInfo{networkType=" + this.a + ", mobileSubtype=" + this.b + "}";
    }
}
