package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class V extends z0 {
    public final String a;
    public final String b;
    public final long c;

    public V(long j, String str, String str2) {
        this.a = str;
        this.b = str2;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof z0) {
            z0 z0Var = (z0) obj;
            if (this.a.equals(((V) z0Var).a)) {
                V v = (V) z0Var;
                if (this.b.equals(v.b) && this.c == v.c) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        long j = this.c;
        return iHashCode ^ ((int) ((j >>> 32) ^ j));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Signal{name=");
        sb.append(this.a);
        sb.append(", code=");
        sb.append(this.b);
        sb.append(", address=");
        return android.support.v4.media.session.a.g(this.c, "}", sb);
    }
}
