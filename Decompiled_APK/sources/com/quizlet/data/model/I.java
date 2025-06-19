package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class I {
    public final long a;
    public final String b;
    public final int c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final long h;
    public final Y1 i;
    public final String j;
    public final boolean k;
    public final int l;
    public final boolean m;
    public final long n;
    public final long o;
    public final String p;

    public I(long j, String setName, int i, boolean z, boolean z2, boolean z3, boolean z4, long j2, Y1 type, String str, boolean z5, int i2, boolean z6, long j3, long j4, String str2) {
        Intrinsics.checkNotNullParameter(setName, "setName");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = j;
        this.b = setName;
        this.c = i;
        this.d = z;
        this.e = z2;
        this.f = z3;
        this.g = z4;
        this.h = j2;
        this.i = type;
        this.j = str;
        this.k = z5;
        this.l = i2;
        this.m = z6;
        this.n = j3;
        this.o = j4;
        this.p = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return this.a == i.a && Intrinsics.b(this.b, i.b) && this.c == i.c && this.d == i.d && this.e == i.e && this.f == i.f && this.g == i.g && this.h == i.h && this.i == i.i && Intrinsics.b(this.j, i.j) && this.k == i.k && this.l == i.l && this.m == i.m && this.n == i.n && this.o == i.o && Intrinsics.b(this.p, i.p);
    }

    public final int hashCode() {
        int iHashCode = (this.i.hashCode() + androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h)) * 31;
        String str = this.j;
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.l, androidx.compose.animation.d0.g((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.k), 31), 31, this.m), 31, this.n), 31, this.o);
        String str2 = this.p;
        return iD + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContentStudySetCard(id=");
        sb.append(this.a);
        sb.append(", setName=");
        sb.append(this.b);
        sb.append(", terms=");
        sb.append(this.c);
        sb.append(", hasImages=");
        sb.append(this.d);
        sb.append(", hasDiagrams=");
        sb.append(this.e);
        sb.append(", isLocked=");
        sb.append(this.f);
        sb.append(", isDraft=");
        sb.append(this.g);
        sb.append(", sortTimestamp=");
        sb.append(this.h);
        sb.append(", type=");
        sb.append(this.i);
        sb.append(", accessCodePrefix=");
        sb.append(this.j);
        sb.append(", passwordUse=");
        sb.append(this.k);
        sb.append(", accessType=");
        sb.append(this.l);
        sb.append(", deleted=");
        sb.append(this.m);
        sb.append(", publishedTimestamp=");
        sb.append(this.n);
        sb.append(", timestamp=");
        sb.append(this.o);
        sb.append(", thumbnailUrl=");
        return android.support.v4.media.session.a.t(sb, this.p, ")");
    }
}
