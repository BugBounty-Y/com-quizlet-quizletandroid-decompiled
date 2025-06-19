package com.quizlet.features.folders.menu;

import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends q {
    public final String a;
    public final y1 b;

    public p(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && this.b == pVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RemoveFromFolder(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ")";
    }
}
