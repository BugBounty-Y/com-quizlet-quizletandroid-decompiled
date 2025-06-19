package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class U extends y0 {
    public final String a;
    public final String b;
    public final List c;
    public final y0 d;
    public final int e;

    public U(String str, String str2, List list, y0 y0Var, int i) {
        this.a = str;
        this.b = str2;
        this.c = list;
        this.d = y0Var;
        this.e = i;
    }

    public final boolean equals(Object obj) {
        String str;
        if (obj == this) {
            return true;
        }
        if (obj instanceof y0) {
            y0 y0Var = (y0) obj;
            if (this.a.equals(((U) y0Var).a) && ((str = this.b) != null ? str.equals(((U) y0Var).b) : ((U) y0Var).b == null)) {
                U u = (U) y0Var;
                if (this.c.equals(u.c)) {
                    y0 y0Var2 = u.d;
                    y0 y0Var3 = this.d;
                    if (y0Var3 != null ? y0Var3.equals(y0Var2) : y0Var2 == null) {
                        if (this.e == u.e) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (this.a.hashCode() ^ 1000003) * 1000003;
        String str = this.b;
        int iHashCode2 = (((iHashCode ^ (str == null ? 0 : str.hashCode())) * 1000003) ^ this.c.hashCode()) * 1000003;
        y0 y0Var = this.d;
        return ((iHashCode2 ^ (y0Var != null ? y0Var.hashCode() : 0)) * 1000003) ^ this.e;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Exception{type=");
        sb.append(this.a);
        sb.append(", reason=");
        sb.append(this.b);
        sb.append(", frames=");
        sb.append(this.c);
        sb.append(", causedBy=");
        sb.append(this.d);
        sb.append(", overflowCount=");
        return android.support.v4.media.session.a.r(sb, this.e, "}");
    }
}
