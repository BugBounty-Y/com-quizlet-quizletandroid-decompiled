package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4107a0 {
    public final Object a;
    public final A1 b;
    public final String c;

    static {
        new C4107a0(kotlin.collections.K.a, null, "");
    }

    public C4107a0(List list, A1 a1, String searchSessionId) {
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.a = list;
        this.b = a1;
        this.c = searchSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4107a0)) {
            return false;
        }
        C4107a0 c4107a0 = (C4107a0) obj;
        return Intrinsics.b(this.a, c4107a0.a) && Intrinsics.b(this.b, c4107a0.b) && this.c.equals(c4107a0.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        A1 a1 = this.b;
        return this.c.hashCode() + ((iHashCode + (a1 == null ? 0 : a1.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExplanationsSearchResults(list=");
        sb.append(this.a);
        sb.append(", pagingKey=");
        sb.append(this.b);
        sb.append(", searchSessionId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
