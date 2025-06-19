package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.y1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4183y1 {
    public static final C4183y1 c;
    public final C4172v a;
    public final String b;

    static {
        kotlin.collections.K k = kotlin.collections.K.a;
        c = new C4183y1(new C4172v(k, k, k, k, k, k, k), "");
    }

    public C4183y1(C4172v allResultsSearchResult, String searchSessionId) {
        Intrinsics.checkNotNullParameter(allResultsSearchResult, "allResultsSearchResult");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.a = allResultsSearchResult;
        this.b = searchSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4183y1)) {
            return false;
        }
        C4183y1 c4183y1 = (C4183y1) obj;
        return Intrinsics.b(this.a, c4183y1.a) && Intrinsics.b(this.b, c4183y1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SearchAllResultsWrapper(allResultsSearchResult=" + this.a + ", searchSessionId=" + this.b + ")";
    }
}
