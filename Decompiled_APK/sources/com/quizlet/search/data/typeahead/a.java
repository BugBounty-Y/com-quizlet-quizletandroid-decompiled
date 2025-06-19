package com.quizlet.search.data.typeahead;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;

    public a(String userQuery, String suggestedQuery) {
        Intrinsics.checkNotNullParameter(userQuery, "userQuery");
        Intrinsics.checkNotNullParameter(suggestedQuery, "suggestedQuery");
        this.a = userQuery;
        this.b = suggestedQuery;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchTypeAheadData(userQuery=");
        sb.append(this.a);
        sb.append(", suggestedQuery=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
