package com.quizlet.features.folders.data;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.t0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4308t0 implements InterfaceC4312v0 {
    public final AddMaterialFolderData a;

    public C4308t0(AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(addMaterialFolderData, "addMaterialFolderData");
        this.a = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4308t0) && Intrinsics.b(this.a, ((C4308t0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GoToUploadFlashcards(addMaterialFolderData=" + this.a + ")";
    }
}
