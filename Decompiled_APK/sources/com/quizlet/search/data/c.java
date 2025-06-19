package com.quizlet.search.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final String b;
    public final com.quizlet.data.model.search.b c;

    public c(String originalQuery, String correctedQuery, com.quizlet.data.model.search.b misspellingsType) {
        Intrinsics.checkNotNullParameter(originalQuery, "originalQuery");
        Intrinsics.checkNotNullParameter(correctedQuery, "correctedQuery");
        Intrinsics.checkNotNullParameter(misspellingsType, "misspellingsType");
        this.a = originalQuery;
        this.b = correctedQuery;
        this.c = misspellingsType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "SearchMisspellingsData(originalQuery=" + this.a + ", correctedQuery=" + this.b + ", misspellingsType=" + this.c + ")";
    }
}
