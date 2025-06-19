package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class o extends B {
    public final r a;

    public o(r rVar) {
        A a = A.a;
        this.a = rVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        if (!this.a.equals(((o) b).a)) {
            return false;
        }
        Object obj2 = A.a;
        ((o) b).getClass();
        return obj2.equals(obj2);
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ A.a.hashCode();
    }

    public final String toString() {
        return "ComplianceData{privacyContext=" + this.a + ", productIdOrigin=" + A.a + "}";
    }
}
