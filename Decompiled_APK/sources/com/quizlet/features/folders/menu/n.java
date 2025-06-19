package com.quizlet.features.folders.menu;

import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends q {
    public final String a;
    public final y1 b;

    public n(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AddOrRemoveTags(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ")";
    }
}
