package com.quizlet.features.infra.folder.menu.data;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final y1 b;
    public final AddMaterialFolderData c;

    public a(String studyMaterialId, y1 studyMaterialType, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        Intrinsics.checkNotNullParameter(addMaterialFolderData, "addMaterialFolderData");
        this.a = studyMaterialId;
        this.b = studyMaterialType;
        this.c = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "AddMaterialFolderDataEvent(studyMaterialId=" + this.a + ", studyMaterialType=" + this.b + ", addMaterialFolderData=" + this.c + ")";
    }
}
