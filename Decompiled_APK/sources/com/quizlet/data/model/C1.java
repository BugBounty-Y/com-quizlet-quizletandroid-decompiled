package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C1 {
    public final String a;
    public final List b;

    public C1(String searchSessionId, List suggestions) {
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        Intrinsics.checkNotNullParameter(suggestions, "suggestions");
        this.a = searchSessionId;
        this.b = suggestions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1)) {
            return false;
        }
        C1 c1 = (C1) obj;
        return Intrinsics.b(this.a, c1.a) && Intrinsics.b(this.b, c1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SearchSuggestionWrapper(searchSessionId=" + this.a + ", suggestions=" + this.b + ")";
    }

    public C1() {
        this("", kotlin.collections.K.a);
    }
}
