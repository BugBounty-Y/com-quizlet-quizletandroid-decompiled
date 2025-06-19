package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class M {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;

    public M(String plainText, String languageCode, String str, String str2, String str3) {
        Intrinsics.checkNotNullParameter(plainText, "plainText");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = plainText;
        this.b = languageCode;
        this.c = str;
        this.d = str2;
        this.e = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return Intrinsics.b(this.a, m.a) && Intrinsics.b(this.b, m.b) && Intrinsics.b(this.c, m.c) && Intrinsics.b(this.d, m.d) && Intrinsics.b(this.e, m.e);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CustomTextDistractor(plainText=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", ttsUrl=");
        sb.append(this.c);
        sb.append(", ttsSlowUrl=");
        sb.append(this.d);
        sb.append(", richTextJson=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
