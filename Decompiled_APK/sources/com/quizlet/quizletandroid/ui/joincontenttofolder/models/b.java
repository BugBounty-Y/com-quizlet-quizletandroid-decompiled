package com.quizlet.quizletandroid.ui.joincontenttofolder.models;

import com.quizlet.data.model.CreatedFolder;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends c {
    public final CreatedFolder a;
    public final d b;
    public final boolean c;

    public b(CreatedFolder folder, d dVar, boolean z) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = dVar;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && this.c == bVar.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        d dVar = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (dVar == null ? 0 : dVar.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderItem(folder=");
        sb.append(this.a);
        sb.append(", userDisplayInfo=");
        sb.append(this.b);
        sb.append(", isSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
