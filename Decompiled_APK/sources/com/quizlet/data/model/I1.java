package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class I1 implements M1 {
    public final String a;
    public final com.quizlet.generated.enums.y1 b;

    public I1(String studyMaterialId, com.quizlet.generated.enums.y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
    }

    @Override // com.quizlet.data.model.M1
    public final com.quizlet.generated.enums.y1 b() {
        return this.b;
    }

    @Override // com.quizlet.data.model.M1
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I1)) {
            return false;
        }
        I1 i1 = (I1) obj;
        return Intrinsics.b(this.a, i1.a) && this.b == i1.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SimpleStudyMaterial(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ")";
    }
}
