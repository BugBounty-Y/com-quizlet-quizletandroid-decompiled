package com.quizlet.features.folders.menu;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements i {
    public final String a;
    public final String b;
    public final long c;

    public h(long j, String str, String folderName) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        this.a = str;
        this.b = folderName;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b) && this.c == hVar.c;
    }

    public final int hashCode() {
        String str = this.a;
        return Long.hashCode(this.c) + d0.e((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
    }

    @Override // com.quizlet.features.folders.menu.i
    public final boolean isEnabled() {
        return true;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShareFolder(url=");
        sb.append(this.a);
        sb.append(", folderName=");
        sb.append(this.b);
        sb.append(", folderId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
