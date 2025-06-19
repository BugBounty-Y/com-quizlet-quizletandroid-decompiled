package com.quizlet.features.setpage.header.data;

import com.quizlet.data.model.O1;
import com.quizlet.data.model.Q1;
import com.quizlet.features.infra.models.Creator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public static final d g;
    public final com.quizlet.qutils.string.g a;
    public final com.quizlet.qutils.string.g b;
    public final com.quizlet.qutils.string.g c;
    public final com.quizlet.qutils.string.g d;
    public final Creator e;
    public final Q1 f;

    static {
        Intrinsics.checkNotNullParameter("", "string");
        com.quizlet.qutils.string.e eVar = new com.quizlet.qutils.string.e("");
        Intrinsics.checkNotNullParameter("", "string");
        com.quizlet.qutils.string.e eVar2 = new com.quizlet.qutils.string.e("");
        Intrinsics.checkNotNullParameter("", "string");
        g = new d(eVar, eVar2, null, new com.quizlet.qutils.string.e(""), null, O1.a);
    }

    public d(com.quizlet.qutils.string.g headerTitle, com.quizlet.qutils.string.g termCount, com.quizlet.qutils.string.g gVar, com.quizlet.qutils.string.g metadataContentDescription, Creator creator, Q1 modeButtonViewState) {
        Intrinsics.checkNotNullParameter(headerTitle, "headerTitle");
        Intrinsics.checkNotNullParameter(termCount, "termCount");
        Intrinsics.checkNotNullParameter(metadataContentDescription, "metadataContentDescription");
        Intrinsics.checkNotNullParameter(modeButtonViewState, "modeButtonViewState");
        this.a = headerTitle;
        this.b = termCount;
        this.c = gVar;
        this.d = metadataContentDescription;
        this.e = creator;
        this.f = modeButtonViewState;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v2, types: [com.quizlet.qutils.string.g] */
    /* JADX WARN: Type inference failed for: r11v2, types: [com.quizlet.qutils.string.g] */
    /* JADX WARN: Type inference failed for: r8v7, types: [com.quizlet.qutils.string.g] */
    /* JADX WARN: Type inference failed for: r9v2, types: [com.quizlet.qutils.string.g] */
    public static d a(d dVar, com.quizlet.qutils.string.e eVar, com.quizlet.qutils.string.d dVar2, com.quizlet.qutils.string.e eVar2, com.quizlet.qutils.string.d dVar3, Creator creator, Q1 q1, int i) {
        com.quizlet.qutils.string.e eVar3 = eVar;
        if ((i & 1) != 0) {
            eVar3 = dVar.a;
        }
        com.quizlet.qutils.string.e headerTitle = eVar3;
        com.quizlet.qutils.string.d dVar4 = dVar2;
        if ((i & 2) != 0) {
            dVar4 = dVar.b;
        }
        com.quizlet.qutils.string.d termCount = dVar4;
        com.quizlet.qutils.string.e eVar4 = eVar2;
        if ((i & 4) != 0) {
            eVar4 = dVar.c;
        }
        com.quizlet.qutils.string.e eVar5 = eVar4;
        com.quizlet.qutils.string.d dVar5 = dVar3;
        if ((i & 8) != 0) {
            dVar5 = dVar.d;
        }
        com.quizlet.qutils.string.d metadataContentDescription = dVar5;
        if ((i & 16) != 0) {
            creator = dVar.e;
        }
        Creator creator2 = creator;
        if ((i & 32) != 0) {
            q1 = dVar.f;
        }
        Q1 modeButtonViewState = q1;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(headerTitle, "headerTitle");
        Intrinsics.checkNotNullParameter(termCount, "termCount");
        Intrinsics.checkNotNullParameter(metadataContentDescription, "metadataContentDescription");
        Intrinsics.checkNotNullParameter(modeButtonViewState, "modeButtonViewState");
        return new d(headerTitle, termCount, eVar5, metadataContentDescription, creator2, modeButtonViewState);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c) && Intrinsics.b(this.d, dVar.d) && Intrinsics.b(this.e, dVar.e) && Intrinsics.b(this.f, dVar.f);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        com.quizlet.qutils.string.g gVar = this.c;
        int iHashCode2 = (this.d.hashCode() + ((iHashCode + (gVar == null ? 0 : gVar.hashCode())) * 31)) * 31;
        Creator creator = this.e;
        return this.f.hashCode() + ((iHashCode2 + (creator != null ? creator.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "SetPageHeaderViewState(headerTitle=" + this.a + ", termCount=" + this.b + ", description=" + this.c + ", metadataContentDescription=" + this.d + ", creator=" + this.e + ", modeButtonViewState=" + this.f + ")";
    }
}
