package com.quizlet.features.folders.viewmodel.usecases;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class d {
    public final boolean a;
    public final boolean b;
    public final int c;

    public d(boolean z, boolean z2, int i) {
        this.a = z;
        this.b = z2;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && this.c == dVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderSaveMaterialsResult(addedMaterials=");
        sb.append(this.a);
        sb.append(", removedMaterials=");
        sb.append(this.b);
        sb.append(", itemsChanged=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
