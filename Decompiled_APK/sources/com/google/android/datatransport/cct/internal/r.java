package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class r extends E {
    public final q a;

    public r(q qVar) {
        this.a = qVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof E) {
            return this.a.equals(((r) ((E) obj)).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return "ExternalPrivacyContext{prequest=" + this.a + "}";
    }
}
