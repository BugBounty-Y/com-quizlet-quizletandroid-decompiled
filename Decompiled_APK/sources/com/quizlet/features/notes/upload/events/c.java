package com.quizlet.features.notes.upload.events;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements i {
    public final String a;
    public final boolean b;
    public final AddMaterialFolderData c;

    public c(String noteId, boolean z, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(noteId, "noteId");
        this.a = noteId;
        this.b = z;
        this.c = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        AddMaterialFolderData addMaterialFolderData = this.c;
        return iG + (addMaterialFolderData == null ? 0 : addMaterialFolderData.hashCode());
    }

    public final String toString() {
        return "MagicNotesDetail(noteId=" + this.a + ", displayFlashcardsOnly=" + this.b + ", addMaterialFolderData=" + this.c + ")";
    }
}
