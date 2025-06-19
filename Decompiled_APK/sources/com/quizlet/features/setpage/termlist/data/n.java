package com.quizlet.features.setpage.termlist.data;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends p {
    public final List a;
    public final a b;
    public final Set c;
    public final m d;
    public final boolean e;
    public final b f;

    public n(List terms, a diagramData, Set set, m termListSortOption, boolean z) {
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(termListSortOption, "termListSortOption");
        this.a = terms;
        this.b = diagramData;
        this.c = set;
        this.d = termListSortOption;
        this.e = z;
        this.f = new b(set != null ? set.size() : 0, z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v2, types: [java.util.Set] */
    public static n a(n nVar, List list, LinkedHashSet linkedHashSet, m mVar, boolean z, int i) {
        if ((i & 1) != 0) {
            list = nVar.a;
        }
        List terms = list;
        a diagramData = nVar.b;
        LinkedHashSet linkedHashSet2 = linkedHashSet;
        if ((i & 4) != 0) {
            linkedHashSet2 = nVar.c;
        }
        LinkedHashSet linkedHashSet3 = linkedHashSet2;
        if ((i & 8) != 0) {
            mVar = nVar.d;
        }
        m termListSortOption = mVar;
        if ((i & 16) != 0) {
            z = nVar.e;
        }
        nVar.getClass();
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(termListSortOption, "termListSortOption");
        return new n(terms, diagramData, linkedHashSet3, termListSortOption, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b) && Intrinsics.b(this.c, nVar.c) && this.d == nVar.d && this.e == nVar.e;
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        Set set = this.c;
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + ((iHashCode + (set == null ? 0 : set.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(terms=");
        sb.append(this.a);
        sb.append(", diagramData=");
        sb.append(this.b);
        sb.append(", selectedTermIds=");
        sb.append(this.c);
        sb.append(", termListSortOption=");
        sb.append(this.d);
        sb.append(", isControlStateSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
