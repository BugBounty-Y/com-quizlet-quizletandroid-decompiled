package com.quizlet.features.notes.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z {
    public final com.quizlet.utmhelper.a a;
    public final String b;
    public final String c;

    public z(com.quizlet.utmhelper.a utmInfo, String id, String url) {
        Intrinsics.checkNotNullParameter(utmInfo, "utmInfo");
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = utmInfo;
        this.b = id;
        this.c = url;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return Intrinsics.b(this.a, zVar.a) && Intrinsics.b(this.b, zVar.b) && Intrinsics.b(this.c, zVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShareNotesData(utmInfo=");
        sb.append(this.a);
        sb.append(", id=");
        sb.append(this.b);
        sb.append(", url=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
