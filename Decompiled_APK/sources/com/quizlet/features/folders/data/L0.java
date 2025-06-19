package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L0 implements P0 {
    public final kotlinx.collections.immutable.b a;
    public final boolean b;
    public final String c;
    public final K0 d;

    public L0(kotlinx.collections.immutable.b studyMaterials, boolean z, String str, K0 sortType) {
        Intrinsics.checkNotNullParameter(studyMaterials, "studyMaterials");
        Intrinsics.checkNotNullParameter(sortType, "sortType");
        this.a = studyMaterials;
        this.b = z;
        this.c = str;
        this.d = sortType;
    }

    public static L0 d(L0 l0, kotlinx.collections.immutable.b studyMaterials, boolean z, String str, K0 sortType, int i) {
        if ((i & 1) != 0) {
            studyMaterials = l0.a;
        }
        if ((i & 2) != 0) {
            z = l0.b;
        }
        if ((i & 4) != 0) {
            str = l0.c;
        }
        if ((i & 8) != 0) {
            sortType = l0.d;
        }
        Intrinsics.checkNotNullParameter(studyMaterials, "studyMaterials");
        Intrinsics.checkNotNullParameter(sortType, "sortType");
        return new L0(studyMaterials, z, str, sortType);
    }

    @Override // com.quizlet.features.folders.data.P0
    public final kotlinx.collections.immutable.b a() {
        return this.a;
    }

    @Override // com.quizlet.features.folders.data.P0
    public final boolean b() {
        return this.b;
    }

    @Override // com.quizlet.features.folders.data.P0
    public final boolean c() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L0)) {
            return false;
        }
        L0 l0 = (L0) obj;
        return Intrinsics.b(this.a, l0.a) && this.b == l0.b && Intrinsics.b(this.c, l0.c) && Intrinsics.b(this.d, l0.d);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return this.d.hashCode() + ((iG + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        return "Content(studyMaterials=" + this.a + ", showSearchToolbarAction=" + this.b + ", query=" + this.c + ", sortType=" + this.d + ")";
    }
}
