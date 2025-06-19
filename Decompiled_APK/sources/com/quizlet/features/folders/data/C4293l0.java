package com.quizlet.features.folders.data;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.l0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4293l0 implements InterfaceC4312v0 {
    public final AddMaterialFolderData a;

    public C4293l0(AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(addMaterialFolderData, "addMaterialFolderData");
        this.a = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4293l0) && Intrinsics.b(this.a, ((C4293l0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GoToCreateMagicNote(addMaterialFolderData=" + this.a + ")";
    }
}
