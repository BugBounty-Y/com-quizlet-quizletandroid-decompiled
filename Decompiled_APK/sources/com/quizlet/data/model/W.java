package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class W {
    public final String a;
    public final int b;
    public final int c;
    public final String d;

    public W(String contentUrl, int i, String str, int i2) {
        Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
        this.a = contentUrl;
        this.b = i;
        this.c = i2;
        this.d = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof W)) {
            return false;
        }
        W w = (W) obj;
        return Intrinsics.b(this.a, w.a) && this.b == w.b && this.c == w.c && Intrinsics.b(this.d, w.d);
    }

    public final int hashCode() {
        int iB = androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31);
        String str = this.d;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExplanationsFeedback(contentUrl=");
        sb.append(this.a);
        sb.append(", screenWidth=");
        sb.append(this.b);
        sb.append(", screenHeight=");
        sb.append(this.c);
        sb.append(", feedbackContent=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
