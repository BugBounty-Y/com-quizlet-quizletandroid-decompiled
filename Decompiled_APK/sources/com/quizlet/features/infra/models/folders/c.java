package com.quizlet.features.infra.models.folders;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public static final c e = new c(-1, b.c, (String) null, 12);
    public final long a;
    public final b b;
    public final String c;
    public final boolean d;

    public c(long j, b subFolderType, String title, boolean z) {
        Intrinsics.checkNotNullParameter(subFolderType, "subFolderType");
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = j;
        this.b = subFolderType;
        this.c = title;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.e((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "SubFolderUiData(id=" + this.a + ", subFolderType=" + this.b + ", title=" + this.c + ", enabled=" + this.d + ")";
    }

    public /* synthetic */ c(long j, b bVar, String str, int i) {
        this(j, bVar, (i & 4) != 0 ? "" : str, true);
    }
}
