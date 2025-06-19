package com.quizlet.explanations.textbook.data;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class u {
    public final boolean a;
    public final boolean b;
    public final String c;
    public final y1 d;

    public u(boolean z, boolean z2, String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = z;
        this.b = z2;
        this.c = studyMaterialId;
        this.d = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return this.a == uVar.a && this.b == uVar.b && Intrinsics.b(this.c, uVar.c) && this.d == uVar.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "TextbookToolbarState(indicatorAsClose=" + this.a + ", canAddToFolder=" + this.b + ", studyMaterialId=" + this.c + ", studyMaterialType=" + this.d + ")";
    }
}
