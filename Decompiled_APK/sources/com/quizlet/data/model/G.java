package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class G {
    public final ContentFolder a;
    public final User b;
    public final long c;
    public final boolean d;

    public G(ContentFolder folder, User user, long j, boolean z) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = user;
        this.c = j;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return Intrinsics.b(this.a, g.a) && Intrinsics.b(this.b, g.b) && this.c == g.c && this.d == g.d;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return Boolean.hashCode(this.d) + androidx.compose.animation.d0.d((iHashCode + (user == null ? 0 : user.hashCode())) * 31, 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContentFolderWithCreatorInClass(folder=");
        sb.append(this.a);
        sb.append(", creator=");
        sb.append(this.b);
        sb.append(", timestampAddedSec=");
        sb.append(this.c);
        sb.append(", canEdit=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
