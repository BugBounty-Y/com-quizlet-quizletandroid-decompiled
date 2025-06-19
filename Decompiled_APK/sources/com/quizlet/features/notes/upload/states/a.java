package com.quizlet.features.notes.upload.states;

import androidx.compose.animation.d0;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final m2 a;
    public final int b;
    public final int c;
    public final boolean d;
    public final boolean e;
    public final AddMaterialFolderData f;

    public a(m2 source, int i, int i2, boolean z, boolean z2, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.b = i;
        this.c = i2;
        this.d = z;
        this.e = z2;
        this.f = addMaterialFolderData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c == aVar.c && this.d == aVar.d && this.e == aVar.e && Intrinsics.b(this.f, aVar.f);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31, this.d), 31, this.e);
        AddMaterialFolderData addMaterialFolderData = this.f;
        return iG + (addMaterialFolderData == null ? 0 : addMaterialFolderData.hashCode());
    }

    public final String toString() {
        return "Idle(source=" + this.a + ", maximumCharacter=" + this.b + ", minimumCharacter=" + this.c + ", isPrivacyVisible=" + this.d + ", isToastVisible=" + this.e + ", addMaterialFolderData=" + this.f + ")";
    }
}
