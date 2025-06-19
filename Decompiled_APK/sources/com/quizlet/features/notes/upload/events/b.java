package com.quizlet.features.notes.upload.events;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements i {
    public final AddMaterialFolderData a;

    public b(AddMaterialFolderData addMaterialFolderData) {
        this.a = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        AddMaterialFolderData addMaterialFolderData = this.a;
        if (addMaterialFolderData == null) {
            return 0;
        }
        return addMaterialFolderData.hashCode();
    }

    public final String toString() {
        return "CreateSet(addMaterialFolderData=" + this.a + ")";
    }
}
