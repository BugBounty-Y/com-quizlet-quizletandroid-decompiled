package com.quizlet.data.interactor.folderstudymaterial;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements g {
    public final String a;
    public final y1 b;
    public final List c;
    public final List d;

    public e(String studyMaterialId, y1 studyMaterialType, List selectedFolderIds, List currentFolderIds) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        Intrinsics.checkNotNullParameter(selectedFolderIds, "selectedFolderIds");
        Intrinsics.checkNotNullParameter(currentFolderIds, "currentFolderIds");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
        this.c = selectedFolderIds;
        this.d = currentFolderIds;
    }

    @Override // com.quizlet.data.interactor.folderstudymaterial.g
    public final y1 b() {
        return this.b;
    }

    @Override // com.quizlet.data.interactor.folderstudymaterial.g
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.f((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "Multi(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ", selectedFolderIds=" + this.c + ", currentFolderIds=" + this.d + ")";
    }
}
