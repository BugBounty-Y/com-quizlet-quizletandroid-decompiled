package com.quizlet.data.interactor.folderstudymaterial;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements g {
    public final long a;
    public final String b;
    public final y1 c;

    public d(long j, String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = j;
        this.b = studyMaterialId;
        this.c = studyMaterialType;
        A.b(Long.valueOf(j));
    }

    @Override // com.quizlet.data.interactor.folderstudymaterial.g
    public final y1 b() {
        return this.c;
    }

    @Override // com.quizlet.data.interactor.folderstudymaterial.g
    public final String c() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "Add(folderId=" + this.a + ", studyMaterialId=" + this.b + ", studyMaterialType=" + this.c + ")";
    }
}
