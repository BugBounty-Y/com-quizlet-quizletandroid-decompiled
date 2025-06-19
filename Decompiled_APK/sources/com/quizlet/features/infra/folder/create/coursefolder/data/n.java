package com.quizlet.features.infra.folder.create.coursefolder.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final String a;
    public final long b;
    public final long c;

    public n(long j, long j2, String folderTitle) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        Intrinsics.checkNotNullParameter("", "folderDescription");
        this.a = folderTitle;
        this.b = j;
        this.c = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b && this.c == nVar.c;
    }

    public final int hashCode() {
        return d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SaveFolderData(folderTitle=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", courseId=");
        return android.support.v4.media.session.a.g(this.c, ", folderDescription=)", sb);
    }
}
