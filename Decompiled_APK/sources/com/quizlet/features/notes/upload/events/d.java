package com.quizlet.features.notes.upload.events;

import androidx.compose.animation.d0;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements i {
    public final boolean a;
    public final m2 b;
    public final String c;
    public final AddMaterialFolderData d;

    public d(boolean z, m2 source, String text, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = z;
        this.b = source;
        this.c = text;
        this.d = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && Intrinsics.b(this.c, dVar.c) && Intrinsics.b(this.d, dVar.d);
    }

    public final int hashCode() {
        int iE = d0.e((this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31, 31, this.c);
        AddMaterialFolderData addMaterialFolderData = this.d;
        return iE + (addMaterialFolderData == null ? 0 : addMaterialFolderData.hashCode());
    }

    public final String toString() {
        return "PasteText(isPrivate=" + this.a + ", source=" + this.b + ", text=" + this.c + ", addMaterialFolderData=" + this.d + ")";
    }
}
