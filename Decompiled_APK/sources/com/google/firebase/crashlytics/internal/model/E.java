package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class E extends p0 {
    public final String a;
    public final String b;
    public final String c;

    public E(String str, String str2, String str3) {
        this.a = str;
        this.b = str2;
        this.c = str3;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof p0) {
            p0 p0Var = (p0) obj;
            if (this.a.equals(((E) p0Var).a)) {
                E e = (E) p0Var;
                if (this.b.equals(e.b) && this.c.equals(e.c)) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BuildIdMappingForArch{arch=");
        sb.append(this.a);
        sb.append(", libraryName=");
        sb.append(this.b);
        sb.append(", buildId=");
        return android.support.v4.media.session.a.t(sb, this.c, "}");
    }
}
