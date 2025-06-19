package com.quizlet.features.infra.models.folders;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.Creator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final String b;
    public final long c;
    public final Creator d;

    public a(long j, String name, long j2, Creator creator) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = name;
        this.c = j2;
        this.d = creator;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        int iD = d0.d(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
        Creator creator = this.d;
        return iD + (creator == null ? 0 : creator.hashCode());
    }

    public final String toString() {
        return "Folder(folderId=" + this.a + ", name=" + this.b + ", personId=" + this.c + ", creator=" + this.d + ")";
    }
}
