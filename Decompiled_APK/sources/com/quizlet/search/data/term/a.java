package com.quizlet.search.data.term;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final long b;
    public final String c;
    public final int d;
    public final e e;
    public final TermUiModel f;
    public final ArrayList g;

    public a(long j, long j2, String setName, int i, e setCreator, TermUiModel highlightedTerm, ArrayList terms) {
        Intrinsics.checkNotNullParameter(setName, "setName");
        Intrinsics.checkNotNullParameter(setCreator, "setCreator");
        Intrinsics.checkNotNullParameter(highlightedTerm, "highlightedTerm");
        Intrinsics.checkNotNullParameter(terms, "terms");
        this.a = j;
        this.b = j2;
        this.c = setName;
        this.d = i;
        this.e = setCreator;
        this.f = highlightedTerm;
        this.g = terms;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && this.d == aVar.d && this.e.equals(aVar.e) && Intrinsics.b(this.f, aVar.f) && this.g.equals(aVar.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + d0.b(this.d, d0.e(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FullTermSearchUiModel(termId=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", setName=");
        sb.append(this.c);
        sb.append(", termCount=");
        sb.append(this.d);
        sb.append(", setCreator=");
        sb.append(this.e);
        sb.append(", highlightedTerm=");
        sb.append(this.f);
        sb.append(", terms=");
        return AbstractC0147y.f(")", sb, this.g);
    }
}
