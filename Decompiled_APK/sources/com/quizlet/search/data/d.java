package com.quizlet.search.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;
    public final String b;

    public d(String searchSessionId, String query) {
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        Intrinsics.checkNotNullParameter(query, "query");
        this.a = searchSessionId;
        this.b = query;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchTypeAheadLoggingData(searchSessionId=");
        sb.append(this.a);
        sb.append(", query=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
