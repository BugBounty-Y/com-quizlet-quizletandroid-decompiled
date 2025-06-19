package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudySet {
    public final boolean A;
    public final boolean B;
    public final Boolean C;
    public final long a;
    public final int b;
    public final int c;
    public final int d;
    public final long e;
    public final String f;
    public final String g;
    public final String h;
    public final boolean i;
    public final boolean j;
    public final int k;
    public final String l;
    public final String m;
    public final int n;
    public final boolean o;
    public final int p;
    public final int q;
    public final int r;
    public final boolean s;
    public final String t;
    public final String u;
    public final String v;
    public final int w;
    public final long x;
    public final boolean y;
    public final Long z;

    public StudySet(long j, int i, int i2, int i3, long j2, String wordLang, String defLang, String title, boolean z, boolean z2, int i4, String str, String description, int i5, boolean z3, int i6, int i7, int i8, boolean z4, String webUrl, String str2, String str3, int i9, long j3, boolean z5, Long l, boolean z6, boolean z7, Boolean bool) {
        Intrinsics.checkNotNullParameter(wordLang, "wordLang");
        Intrinsics.checkNotNullParameter(defLang, "defLang");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        this.a = j;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = j2;
        this.f = wordLang;
        this.g = defLang;
        this.h = title;
        this.i = z;
        this.j = z2;
        this.k = i4;
        this.l = str;
        this.m = description;
        this.n = i5;
        this.o = z3;
        this.p = i6;
        this.q = i7;
        this.r = i8;
        this.s = z4;
        this.t = webUrl;
        this.u = str2;
        this.v = str3;
        this.w = i9;
        this.x = j3;
        this.y = z5;
        this.z = l;
        this.A = z6;
        this.B = z7;
        this.C = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!StudySet.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type com.quizlet.data.model.StudySet");
        StudySet studySet = (StudySet) obj;
        return this.a == studySet.a && this.b == studySet.b && this.c == studySet.c && this.d == studySet.d && this.e == studySet.e && Intrinsics.b(this.f, studySet.f) && Intrinsics.b(this.g, studySet.g) && Intrinsics.b(this.h, studySet.h) && this.i == studySet.i && this.j == studySet.j && this.k == studySet.k && Intrinsics.b(this.l, studySet.l) && Intrinsics.b(this.m, studySet.m) && this.n == studySet.n && this.o == studySet.o && this.p == studySet.p && this.q == studySet.q && this.r == studySet.r && this.s == studySet.s && Intrinsics.b(this.t, studySet.t) && Intrinsics.b(this.u, studySet.u) && Intrinsics.b(this.v, studySet.v) && this.w == studySet.w && this.x == studySet.x && this.y == studySet.y && this.A == studySet.A && this.B == studySet.B;
    }

    public final int hashCode() {
        int iG = (androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(((((((Long.hashCode(this.a) * 31) + this.b) * 31) + this.c) * 31) + this.d) * 31, 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j) + this.k) * 31;
        String str = this.l;
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.g((((((androidx.compose.animation.d0.g((androidx.compose.animation.d0.e((iG + (str != null ? str.hashCode() : 0)) * 31, 31, this.m) + this.n) * 31, 31, this.o) + this.p) * 31) + this.q) * 31) + this.r) * 31, 31, this.s), 31, this.t);
        String str2 = this.u;
        int iHashCode = (iE + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.v;
        return Boolean.hashCode(this.B) + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d((((iHashCode + (str3 != null ? str3.hashCode() : 0)) * 31) + this.w) * 31, 31, this.x), 31, this.y), 31, this.A);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySet(id=");
        sb.append(this.a);
        sb.append(", timestamp=");
        sb.append(this.b);
        sb.append(", lastModified=");
        sb.append(this.c);
        sb.append(", publishedTimestamp=");
        sb.append(this.d);
        sb.append(", creatorId=");
        sb.append(this.e);
        sb.append(", wordLang=");
        sb.append(this.f);
        sb.append(", defLang=");
        sb.append(this.g);
        sb.append(", title=");
        sb.append(this.h);
        sb.append(", passwordUse=");
        sb.append(this.i);
        sb.append(", passwordEdit=");
        sb.append(this.j);
        sb.append(", accessType=");
        sb.append(this.k);
        sb.append(", accessCodePrefix=");
        sb.append(this.l);
        sb.append(", description=");
        sb.append(this.m);
        sb.append(", numTerms=");
        sb.append(this.n);
        sb.append(", hasImages=");
        sb.append(this.o);
        sb.append(", parentId=");
        sb.append(this.p);
        sb.append(", creationSource=");
        sb.append(this.q);
        sb.append(", privacyLockStatus=");
        sb.append(this.r);
        sb.append(", hasDiagrams=");
        sb.append(this.s);
        sb.append(", webUrl=");
        sb.append(this.t);
        sb.append(", thumbnailUrl=");
        sb.append(this.u);
        sb.append(", price=");
        sb.append(this.v);
        sb.append(", purchasableType=");
        sb.append(this.w);
        sb.append(", localId=");
        sb.append(this.x);
        sb.append(", isDeleted=");
        sb.append(this.y);
        sb.append(", clientTimestamp=");
        sb.append(this.z);
        sb.append(", isDirty=");
        sb.append(this.A);
        sb.append(", readyToCreate=");
        sb.append(this.B);
        sb.append(", isEligibleForPracticeTests=");
        return assistantMode.refactored.a.k(sb, this.C, ")");
    }

    public /* synthetic */ StudySet(long j, int i, int i2, int i3, long j2, String str, String str2, String str3, boolean z, boolean z2, int i4, String str4, String str5, int i5, boolean z3, int i6, int i7, int i8, boolean z4, String str6, String str7, String str8, int i9, long j3, boolean z5, Long l, boolean z6, boolean z7, Boolean bool, int i10, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, i, i2, i3, j2, str, str2, str3, z, z2, i4, str4, str5, i5, z3, i6, i7, i8, z4, str6, str7, str8, i9, (i10 & 8388608) != 0 ? 0L : j3, (i10 & 16777216) != 0 ? false : z5, l, (i10 & 67108864) != 0 ? false : z6, (i10 & 134217728) != 0 ? false : z7, (i10 & 268435456) != 0 ? null : bool);
    }
}
