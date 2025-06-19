package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class CreatedFolderStudyMaterial implements InterfaceC4126f0 {
    public final long a;
    public final long b;
    public final String c;
    public final com.quizlet.generated.enums.y1 d;
    public final long e;
    public final long f;

    public CreatedFolderStudyMaterial(long j, long j2, String studyMaterialId, com.quizlet.generated.enums.y1 studyMaterialType, long j3, long j4) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = j;
        this.b = j2;
        this.c = studyMaterialId;
        this.d = studyMaterialType;
        this.e = j3;
        this.f = j4;
    }

    @Override // com.quizlet.data.model.InterfaceC4126f0
    public final long a() {
        return this.f;
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
        if (!(obj instanceof CreatedFolderStudyMaterial)) {
            return false;
        }
        CreatedFolderStudyMaterial createdFolderStudyMaterial = (CreatedFolderStudyMaterial) obj;
        return this.a == createdFolderStudyMaterial.a && this.b == createdFolderStudyMaterial.b && Intrinsics.b(this.c, createdFolderStudyMaterial.c) && this.d == createdFolderStudyMaterial.d && this.e == createdFolderStudyMaterial.e && this.f == createdFolderStudyMaterial.f;
    }

    public final int hashCode() {
        return Long.hashCode(this.f) + androidx.compose.animation.d0.d((this.d.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c)) * 31, 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CreatedFolderStudyMaterial(id=");
        sb.append(this.a);
        sb.append(", folderId=");
        sb.append(this.b);
        sb.append(", studyMaterialId=");
        sb.append(this.c);
        sb.append(", studyMaterialType=");
        sb.append(this.d);
        sb.append(", userId=");
        sb.append(this.e);
        sb.append(", timestampSec=");
        return android.support.v4.media.session.a.g(this.f, ")", sb);
    }
}
