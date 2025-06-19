package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.a2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4109a2 {
    public final Object a;
    public final A1 b;
    public final String c;

    static {
        new C4109a2(kotlin.collections.K.a, null, "");
    }

    public C4109a2(List sets, A1 a1, String sessionId) {
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.a = sets;
        this.b = a1;
        this.c = sessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4109a2)) {
            return false;
        }
        C4109a2 c4109a2 = (C4109a2) obj;
        return Intrinsics.b(this.a, c4109a2.a) && Intrinsics.b(this.b, c4109a2.b) && this.c.equals(c4109a2.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        A1 a1 = this.b;
        return this.c.hashCode() + ((iHashCode + (a1 == null ? 0 : a1.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySetWithCreatorAndPaging(sets=");
        sb.append(this.a);
        sb.append(", paging=");
        sb.append(this.b);
        sb.append(", sessionId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
