package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class w2 {
    public final Object a;
    public final A1 b;
    public final String c;

    static {
        new w2(kotlin.collections.K.a, null, "");
    }

    public w2(List users, A1 a1, String sessionId) {
        Intrinsics.checkNotNullParameter(users, "users");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.a = users;
        this.b = a1;
        this.c = sessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w2)) {
            return false;
        }
        w2 w2Var = (w2) obj;
        return Intrinsics.b(this.a, w2Var.a) && Intrinsics.b(this.b, w2Var.b) && this.c.equals(w2Var.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        A1 a1 = this.b;
        return this.c.hashCode() + ((iHashCode + (a1 == null ? 0 : a1.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UsersWithPaging(users=");
        sb.append(this.a);
        sb.append(", paging=");
        sb.append(this.b);
        sb.append(", sessionId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
