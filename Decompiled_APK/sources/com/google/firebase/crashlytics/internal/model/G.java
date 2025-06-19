package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class G extends t0 {
    public final List a;
    public final String b;

    public G(String str, List list) {
        this.a = list;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        String str;
        if (obj == this) {
            return true;
        }
        if (obj instanceof t0) {
            t0 t0Var = (t0) obj;
            if (this.a.equals(((G) t0Var).a) && ((str = this.b) != null ? str.equals(((G) t0Var).b) : ((G) t0Var).b == null)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (this.a.hashCode() ^ 1000003) * 1000003;
        String str = this.b;
        return iHashCode ^ (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FilesPayload{files=");
        sb.append(this.a);
        sb.append(", orgId=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
