package com.quizlet.shared.httpclient;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;
    public final int b;
    public final String c;

    public b(String str, int i, String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        this.a = str;
        this.b = i;
        this.c = message;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && this.b == bVar.b && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        String str = this.a;
        return this.c.hashCode() + d0.b(this.b, (str == null ? 0 : str.hashCode()) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("HttpResponse(body=");
        sb.append(this.a);
        sb.append(", code=");
        sb.append(this.b);
        sb.append(", message=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
