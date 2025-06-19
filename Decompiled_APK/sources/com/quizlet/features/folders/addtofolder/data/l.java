package com.quizlet.features.folders.addtofolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements n {
    public final s a;
    public final int b;

    public l(s studyMaterial, int i) {
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        this.a = studyMaterial;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && this.b == lVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudyMaterialItemClicked(studyMaterial=" + this.a + ", itemIndex=" + this.b + ")";
    }
}
