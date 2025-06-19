package com.quizlet.features.infra.models.group;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final String b;
    public final String c;

    public a(long j, String title, String str) {
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = j;
        this.b = title;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Group(groupId=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", schoolString=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
