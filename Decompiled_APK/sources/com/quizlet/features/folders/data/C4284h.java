package com.quizlet.features.folders.data;

import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4284h implements T {
    public final String a;
    public final y1 b;

    public C4284h(String materialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(materialId, "materialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = materialId;
        this.b = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4284h)) {
            return false;
        }
        C4284h c4284h = (C4284h) obj;
        return Intrinsics.b(this.a, c4284h.a) && this.b == c4284h.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "DeleteMaterial(materialId=" + this.a + ", studyMaterialType=" + this.b + ")";
    }
}
