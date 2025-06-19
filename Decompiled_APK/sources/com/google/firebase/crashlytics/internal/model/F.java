package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class F extends r0 {
    public final String a;
    public final String b;

    public F(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof r0) {
            r0 r0Var = (r0) obj;
            if (this.a.equals(((F) r0Var).a) && this.b.equals(((F) r0Var).b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CustomAttribute{key=");
        sb.append(this.a);
        sb.append(", value=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
