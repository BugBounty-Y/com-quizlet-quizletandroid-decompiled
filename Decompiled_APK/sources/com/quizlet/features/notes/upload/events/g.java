package com.quizlet.features.notes.upload.events;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements i {
    public final long a;
    public final AddMaterialFolderData b;

    public g(long j, AddMaterialFolderData addMaterialFolderData) {
        this.a = j;
        this.b = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        AddMaterialFolderData addMaterialFolderData = this.b;
        return iHashCode + (addMaterialFolderData == null ? 0 : addMaterialFolderData.hashCode());
    }

    public final String toString() {
        return "SetPage(id=" + this.a + ", addMaterialFolderData=" + this.b + ")";
    }
}
