package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class RecommendedStudyMaterial implements M1 {
    public final String a;
    public final com.quizlet.generated.enums.y1 b;
    public final int c;
    public final boolean d;

    public RecommendedStudyMaterial(String studyMaterialId, com.quizlet.generated.enums.y1 studyMaterialType, int i, boolean z) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
        this.c = i;
        this.d = z;
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
        if (!(obj instanceof RecommendedStudyMaterial)) {
            return false;
        }
        RecommendedStudyMaterial recommendedStudyMaterial = (RecommendedStudyMaterial) obj;
        return Intrinsics.b(this.a, recommendedStudyMaterial.a) && this.b == recommendedStudyMaterial.b && this.c == recommendedStudyMaterial.c && this.d == recommendedStudyMaterial.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + androidx.compose.animation.d0.b(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31);
    }

    public final String toString() {
        return "RecommendedStudyMaterial(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ", rank=" + this.c + ", isPeerRec=" + this.d + ")";
    }
}
