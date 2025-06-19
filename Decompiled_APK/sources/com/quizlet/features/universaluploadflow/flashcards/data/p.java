package com.quizlet.features.universaluploadflow.flashcards.data;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements s {
    public final List a;
    public final boolean b;
    public final int c;
    public final boolean d;
    public final boolean e;

    public p(List flashcardSets, boolean z, int i, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(flashcardSets, "flashcardSets");
        this.a = flashcardSets;
        this.b = z;
        this.c = i;
        this.d = z2;
        this.e = z3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v10, types: [java.util.List] */
    public static p b(p pVar, ArrayList arrayList, int i) {
        ArrayList arrayList2 = arrayList;
        if ((i & 1) != 0) {
            arrayList2 = pVar.a;
        }
        ArrayList flashcardSets = arrayList2;
        boolean z = (i & 2) != 0 ? pVar.b : false;
        boolean z2 = (i & 8) != 0 ? pVar.d : true;
        boolean z3 = (i & 16) != 0 ? pVar.e : false;
        Intrinsics.checkNotNullParameter(flashcardSets, "flashcardSets");
        return new p(flashcardSets, z, pVar.c, z2, z3);
    }

    @Override // com.quizlet.features.universaluploadflow.flashcards.data.s
    public final boolean a() {
        return !false;
    }

    public final ArrayList c() {
        com.quizlet.ui.models.content.listitem.d dVar;
        ArrayList arrayList = new ArrayList();
        for (a aVar : this.a) {
            Long lValueOf = null;
            if (!aVar.d) {
                aVar = null;
            }
            if (aVar != null && (dVar = aVar.a) != null) {
                lValueOf = Long.valueOf(dVar.a);
            }
            if (lValueOf != null) {
                arrayList.add(lValueOf);
            }
        }
        return arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && this.b == pVar.b && this.c == pVar.c && this.d == pVar.d && this.e == pVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.g(d0.b(this.c, d0.g(this.a.hashCode() * 31, 31, this.b), 31), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(flashcardSets=");
        sb.append(this.a);
        sb.append(", shouldShowPrivateSetDialog=");
        sb.append(this.b);
        sb.append(", selectionLimit=");
        sb.append(this.c);
        sb.append(", isLoading=");
        sb.append(this.d);
        sb.append(", errorLoadingContent=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }

    public p(boolean z, int i, List list) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? true : z, 3, false, (i & 16) == 0);
    }
}
