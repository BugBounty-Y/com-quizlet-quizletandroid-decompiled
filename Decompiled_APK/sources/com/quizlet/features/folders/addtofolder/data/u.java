package com.quizlet.features.folders.addtofolder.data;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u {
    public static final List o;
    public static final List p;
    public final List a;
    public final o b;
    public final List c;
    public final r d;
    public final r e;
    public final r f;
    public final r g;
    public final boolean h;
    public final boolean i;
    public final String j;
    public final int k;
    public final List l;
    public final int m;
    public final int n;

    static {
        o oVar = o.a;
        o oVar2 = o.c;
        o = B.j(oVar, oVar2);
        p = B.j(oVar, o.b, oVar2);
    }

    public u(List options, o selectedOption, List createNewMenuOptions, r flashcardSetsData, r studyGuidesData, r expertSolutionsData, r recommendationsData, boolean z, boolean z2, String str, int i, List tabsData, int i2, int i3) {
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
        Intrinsics.checkNotNullParameter(createNewMenuOptions, "createNewMenuOptions");
        Intrinsics.checkNotNullParameter(flashcardSetsData, "flashcardSetsData");
        Intrinsics.checkNotNullParameter(studyGuidesData, "studyGuidesData");
        Intrinsics.checkNotNullParameter(expertSolutionsData, "expertSolutionsData");
        Intrinsics.checkNotNullParameter(recommendationsData, "recommendationsData");
        Intrinsics.checkNotNullParameter(tabsData, "tabsData");
        this.a = options;
        this.b = selectedOption;
        this.c = createNewMenuOptions;
        this.d = flashcardSetsData;
        this.e = studyGuidesData;
        this.f = expertSolutionsData;
        this.g = recommendationsData;
        this.h = z;
        this.i = z2;
        this.j = str;
        this.k = i;
        this.l = tabsData;
        this.m = i2;
        this.n = i3;
    }

    public static u a(u uVar, List list, o oVar, List list2, r rVar, r rVar2, r rVar3, p pVar, boolean z, String str, int i, ArrayList arrayList, int i2, int i3, int i4) {
        List options = (i4 & 1) != 0 ? uVar.a : list;
        o selectedOption = (i4 & 2) != 0 ? uVar.b : oVar;
        List createNewMenuOptions = (i4 & 4) != 0 ? uVar.c : list2;
        r flashcardSetsData = (i4 & 8) != 0 ? uVar.d : rVar;
        r studyGuidesData = (i4 & 16) != 0 ? uVar.e : rVar2;
        r expertSolutionsData = (i4 & 32) != 0 ? uVar.f : rVar3;
        r recommendationsData = (i4 & 64) != 0 ? uVar.g : pVar;
        boolean z2 = (i4 & 128) != 0 ? uVar.h : true;
        boolean z3 = (i4 & 256) != 0 ? uVar.i : z;
        String str2 = (i4 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? uVar.j : str;
        int i5 = (i4 & 1024) != 0 ? uVar.k : i;
        List tabsData = (i4 & 2048) != 0 ? uVar.l : arrayList;
        int i6 = (i4 & 4096) != 0 ? uVar.m : i2;
        int i7 = (i4 & 8192) != 0 ? uVar.n : i3;
        uVar.getClass();
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
        Intrinsics.checkNotNullParameter(createNewMenuOptions, "createNewMenuOptions");
        Intrinsics.checkNotNullParameter(flashcardSetsData, "flashcardSetsData");
        Intrinsics.checkNotNullParameter(studyGuidesData, "studyGuidesData");
        Intrinsics.checkNotNullParameter(expertSolutionsData, "expertSolutionsData");
        Intrinsics.checkNotNullParameter(recommendationsData, "recommendationsData");
        Intrinsics.checkNotNullParameter(tabsData, "tabsData");
        return new u(options, selectedOption, createNewMenuOptions, flashcardSetsData, studyGuidesData, expertSolutionsData, recommendationsData, z2, z3, str2, i5, tabsData, i6, i7);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return Intrinsics.b(this.a, uVar.a) && this.b == uVar.b && Intrinsics.b(this.c, uVar.c) && Intrinsics.b(this.d, uVar.d) && Intrinsics.b(this.e, uVar.e) && Intrinsics.b(this.f, uVar.f) && Intrinsics.b(this.g, uVar.g) && this.h == uVar.h && this.i == uVar.i && Intrinsics.b(this.j, uVar.j) && this.k == uVar.k && Intrinsics.b(this.l, uVar.l) && this.m == uVar.m && this.n == uVar.n;
    }

    public final int hashCode() {
        int iG = d0.g(d0.g((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.f((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c)) * 31)) * 31)) * 31)) * 31, 31, this.h), 31, this.i);
        String str = this.j;
        return Integer.hashCode(this.n) + d0.b(this.m, d0.f(d0.b(this.k, (iG + (str == null ? 0 : str.hashCode())) * 31, 31), 31, this.l), 31);
    }

    public final String toString() {
        return "AddToFolderUiState(options=" + this.a + ", selectedOption=" + this.b + ", createNewMenuOptions=" + this.c + ", flashcardSetsData=" + this.d + ", studyGuidesData=" + this.e + ", expertSolutionsData=" + this.f + ", recommendationsData=" + this.g + ", subFolderEnabled=" + this.h + ", searchMode=" + this.i + ", query=" + this.j + ", selectedTabIndex=" + this.k + ", tabsData=" + this.l + ", itemAddedCount=" + this.m + ", itemRemovedCount=" + this.n + ")";
    }
}
