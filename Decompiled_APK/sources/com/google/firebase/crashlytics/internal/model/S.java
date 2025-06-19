package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class S extends C0 {
    public final List a;
    public final U b;
    public final q0 c;
    public final V d;
    public final List e;

    public S(List list, U u, q0 q0Var, V v, List list2) {
        this.a = list;
        this.b = u;
        this.c = q0Var;
        this.d = v;
        this.e = list2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0)) {
            return false;
        }
        C0 c0 = (C0) obj;
        List list = this.a;
        if (list == null) {
            if (((S) c0).a != null) {
                return false;
            }
        } else if (!list.equals(((S) c0).a)) {
            return false;
        }
        U u = this.b;
        if (u == null) {
            if (((S) c0).b != null) {
                return false;
            }
        } else if (!u.equals(((S) c0).b)) {
            return false;
        }
        q0 q0Var = this.c;
        if (q0Var == null) {
            if (((S) c0).c != null) {
                return false;
            }
        } else if (!q0Var.equals(((S) c0).c)) {
            return false;
        }
        S s = (S) c0;
        return this.d.equals(s.d) && this.e.equals(s.e);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = ((list == null ? 0 : list.hashCode()) ^ 1000003) * 1000003;
        U u = this.b;
        int iHashCode2 = (iHashCode ^ (u == null ? 0 : u.hashCode())) * 1000003;
        q0 q0Var = this.c;
        return (((((q0Var != null ? q0Var.hashCode() : 0) ^ iHashCode2) * 1000003) ^ this.d.hashCode()) * 1000003) ^ this.e.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Execution{threads=");
        sb.append(this.a);
        sb.append(", exception=");
        sb.append(this.b);
        sb.append(", appExitInfo=");
        sb.append(this.c);
        sb.append(", signal=");
        sb.append(this.d);
        sb.append(", binaries=");
        return android.support.v4.media.session.a.n("}", sb, this.e);
    }
}
