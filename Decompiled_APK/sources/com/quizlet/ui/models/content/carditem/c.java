package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final int e;
    public final boolean f;

    public c(int i, long j, String folderName, String username, String userImage, boolean z) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(userImage, "userImage");
        this.a = j;
        this.b = folderName;
        this.c = username;
        this.d = userImage;
        this.e = i;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && Intrinsics.b(this.d, cVar.d) && this.e == cVar.e && this.f == cVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.b(this.e, d0.e(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderCardUiData(folderId=");
        sb.append(this.a);
        sb.append(", folderName=");
        sb.append(this.b);
        sb.append(", username=");
        sb.append(this.c);
        sb.append(", userImage=");
        sb.append(this.d);
        sb.append(", userBadge=");
        sb.append(this.e);
        sb.append(", userIsVerified=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
