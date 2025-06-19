package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class n extends z {
    public final l a;

    public n(l lVar) {
        this.a = lVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        Object obj2 = y.a;
        ((n) zVar).getClass();
        return obj2.equals(obj2) && this.a.equals(((n) zVar).a);
    }

    public final int hashCode() {
        return ((y.a.hashCode() ^ 1000003) * 1000003) ^ this.a.hashCode();
    }

    public final String toString() {
        return "ClientInfo{clientType=" + y.a + ", androidClientInfo=" + this.a + "}";
    }
}
