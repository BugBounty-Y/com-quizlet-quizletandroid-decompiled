package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.j1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4139j1 {
    public final Object a;
    public final A1 b;
    public final String c;

    static {
        new C4139j1(kotlin.collections.K.a, null, "");
    }

    public C4139j1(List qClasses, A1 a1, String sessionId) {
        Intrinsics.checkNotNullParameter(qClasses, "qClasses");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.a = qClasses;
        this.b = a1;
        this.c = sessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4139j1)) {
            return false;
        }
        C4139j1 c4139j1 = (C4139j1) obj;
        return Intrinsics.b(this.a, c4139j1.a) && Intrinsics.b(this.b, c4139j1.b) && this.c.equals(c4139j1.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        A1 a1 = this.b;
        return this.c.hashCode() + ((iHashCode + (a1 == null ? 0 : a1.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QClassesWithSchoolAndPaging(qClasses=");
        sb.append(this.a);
        sb.append(", paging=");
        sb.append(this.b);
        sb.append(", sessionId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
