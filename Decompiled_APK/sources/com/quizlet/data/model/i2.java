package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i2 {
    public final long a;
    public final long b;
    public final long c;
    public final int d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;

    public i2(long j, long j2, long j3, int i, String word, String str, String str2, String str3, String str4, String str5, String str6) {
        Intrinsics.checkNotNullParameter(word, "word");
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = i;
        this.e = word;
        this.f = str;
        this.g = str2;
        this.h = str3;
        this.i = str4;
        this.j = str5;
        this.k = str6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i2)) {
            return false;
        }
        i2 i2Var = (i2) obj;
        return this.a == i2Var.a && this.b == i2Var.b && this.c == i2Var.c && this.d == i2Var.d && Intrinsics.b(this.e, i2Var.e) && Intrinsics.b(this.f, i2Var.f) && Intrinsics.b(this.g, i2Var.g) && Intrinsics.b(this.h, i2Var.h) && Intrinsics.b(this.i, i2Var.i) && Intrinsics.b(this.j, i2Var.j) && Intrinsics.b(this.k, i2Var.k);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31), 31, this.e);
        String str = this.f;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.h;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.i;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.j;
        int iHashCode5 = (iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.k;
        return iHashCode5 + (str6 != null ? str6.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Term(id=");
        sb.append(this.a);
        sb.append(", localId=");
        sb.append(this.b);
        sb.append(", setId=");
        sb.append(this.c);
        sb.append(", rank=");
        sb.append(this.d);
        sb.append(", word=");
        sb.append(this.e);
        sb.append(", definition=");
        sb.append(this.f);
        sb.append(", imageUrl=");
        sb.append(this.g);
        sb.append(", wordRichText=");
        sb.append(this.h);
        sb.append(", definitionRichText=");
        sb.append(this.i);
        sb.append(", wordAudioUrl=");
        sb.append(this.j);
        sb.append(", definitionAudioUrl=");
        return android.support.v4.media.session.a.t(sb, this.k, ")");
    }
}
