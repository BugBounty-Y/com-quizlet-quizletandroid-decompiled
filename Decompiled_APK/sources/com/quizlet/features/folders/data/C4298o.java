package com.quizlet.features.folders.data;

import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4298o implements InterfaceC4296n {
    public final String a;
    public final y1 b;

    public C4298o(String materialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(materialId, "materialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = materialId;
        this.b = studyMaterialType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4298o)) {
            return false;
        }
        C4298o c4298o = (C4298o) obj;
        return Intrinsics.b(this.a, c4298o.a) && this.b == c4298o.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FolderMaterialsMenuClicked(materialId=" + this.a + ", studyMaterialType=" + this.b + ")";
    }
}
