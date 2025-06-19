package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class DeletedFolderStudyMaterial implements InterfaceC4126f0 {
    public final long a;
    public final long b;
    public final String c;
    public final com.quizlet.generated.enums.y1 d;

    public DeletedFolderStudyMaterial(long j, long j2, String studyMaterialId, com.quizlet.generated.enums.y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = j;
        this.b = j2;
        this.c = studyMaterialId;
        this.d = studyMaterialType;
    }

    @Override // com.quizlet.data.model.InterfaceC4126f0
    public final long a() {
        return 0L;
    }

    @Override // com.quizlet.data.model.M1
    public final com.quizlet.generated.enums.y1 b() {
        return this.d;
    }

    @Override // com.quizlet.data.model.M1
    public final String c() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DeletedFolderStudyMaterial)) {
            return false;
        }
        DeletedFolderStudyMaterial deletedFolderStudyMaterial = (DeletedFolderStudyMaterial) obj;
        return this.a == deletedFolderStudyMaterial.a && this.b == deletedFolderStudyMaterial.b && Intrinsics.b(this.c, deletedFolderStudyMaterial.c) && this.d == deletedFolderStudyMaterial.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "DeletedFolderStudyMaterial(id=" + this.a + ", folderId=" + this.b + ", studyMaterialId=" + this.c + ", studyMaterialType=" + this.d + ")";
    }
}
