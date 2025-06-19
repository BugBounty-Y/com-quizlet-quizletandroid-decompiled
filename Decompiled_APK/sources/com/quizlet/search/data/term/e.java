package com.quizlet.search.data.term;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final long a;
    public final String b;
    public final String c;
    public final int d;
    public final boolean e;

    public e(long j, String username, String userImage, int i, boolean z) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(userImage, "userImage");
        this.a = j;
        this.b = username;
        this.c = userImage;
        this.d = i;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && this.d == eVar.d && this.e == eVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.b(this.d, d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TermSearchUserCreator(creatorId=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", userImage=");
        sb.append(this.c);
        sb.append(", userBadge=");
        sb.append(this.d);
        sb.append(", isVerified=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
