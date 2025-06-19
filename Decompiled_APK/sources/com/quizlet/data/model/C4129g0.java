package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4129g0 {
    public final long a;
    public final String b;
    public final com.quizlet.generated.enums.y1 c;

    public C4129g0(long j, String studyMaterialId, com.quizlet.generated.enums.y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = j;
        this.b = studyMaterialId;
        this.c = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4129g0)) {
            return false;
        }
        C4129g0 c4129g0 = (C4129g0) obj;
        return this.a == c4129g0.a && Intrinsics.b(this.b, c4129g0.b) && this.c == c4129g0.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "FolderStudyMaterialData(folderId=" + this.a + ", studyMaterialId=" + this.b + ", studyMaterialType=" + this.c + ")";
    }
}
