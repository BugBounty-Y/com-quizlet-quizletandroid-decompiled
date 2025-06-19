package com.quizlet.search.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends j {
    public final String a;
    public final String b;
    public final c c;

    public f(String inputQuery, String suggestOrMisspelledQuery, c cVar) {
        Intrinsics.checkNotNullParameter(inputQuery, "inputQuery");
        Intrinsics.checkNotNullParameter(suggestOrMisspelledQuery, "suggestOrMisspelledQuery");
        this.a = inputQuery;
        this.b = suggestOrMisspelledQuery;
        this.c = cVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        c cVar = this.c;
        return iE + (cVar == null ? 0 : cVar.hashCode());
    }

    public final String toString() {
        return "Searched(inputQuery=" + this.a + ", suggestOrMisspelledQuery=" + this.b + ", misspellingsData=" + this.c + ")";
    }
}
