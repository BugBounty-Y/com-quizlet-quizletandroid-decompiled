package com.quizlet.shared.models.studyset;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import com.quizlet.shared.models.user.User;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class StudySet extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final User f;
    public final String g;
    public final String h;
    public final String i;
    public final boolean j;
    public final boolean k;
    public final int l;
    public final String m;
    public final String n;
    public final int o;
    public final boolean p;
    public final int q;
    public final int r;
    public final int s;
    public final boolean t;
    public final String u;
    public final String v;
    public final String w;
    public final Boolean x;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudySet$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudySet(int i, long j, long j2, long j3, long j4, User user, String str, String str2, String str3, boolean z, boolean z2, int i2, String str4, String str5, int i3, boolean z3, int i4, int i5, int i6, boolean z4, String str6, String str7, String str8, Boolean bool) {
        if (4194303 != (i & 4194303)) {
            AbstractC5047c0.k(i, 4194303, StudySet$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = j4;
        this.f = user;
        this.g = str;
        this.h = str2;
        this.i = str3;
        this.j = z;
        this.k = z2;
        this.l = i2;
        this.m = str4;
        this.n = str5;
        this.o = i3;
        this.p = z3;
        this.q = i4;
        this.r = i5;
        this.s = i6;
        this.t = z4;
        this.u = str6;
        this.v = str7;
        this.w = str8;
        if ((i & 4194304) == 0) {
            this.x = null;
        } else {
            this.x = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudySet)) {
            return false;
        }
        StudySet studySet = (StudySet) obj;
        return this.b == studySet.b && this.c == studySet.c && this.d == studySet.d && this.e == studySet.e && Intrinsics.b(this.f, studySet.f) && Intrinsics.b(this.g, studySet.g) && Intrinsics.b(this.h, studySet.h) && Intrinsics.b(this.i, studySet.i) && this.j == studySet.j && this.k == studySet.k && this.l == studySet.l && Intrinsics.b(this.m, studySet.m) && Intrinsics.b(this.n, studySet.n) && this.o == studySet.o && this.p == studySet.p && this.q == studySet.q && this.r == studySet.r && this.s == studySet.s && this.t == studySet.t && Intrinsics.b(this.u, studySet.u) && Intrinsics.b(this.v, studySet.v) && Intrinsics.b(this.w, studySet.w) && Intrinsics.b(this.x, studySet.x);
    }

    public final int hashCode() {
        int iB = d0.b(this.l, d0.g(d0.g(d0.e(d0.e(d0.e((this.f.hashCode() + d0.d(d0.d(d0.d(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e)) * 31, 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k), 31);
        String str = this.m;
        int iG = d0.g(d0.b(this.s, d0.b(this.r, d0.b(this.q, d0.g(d0.b(this.o, d0.e((iB + (str == null ? 0 : str.hashCode())) * 31, 31, this.n), 31), 31, this.p), 31), 31), 31), 31, this.t);
        String str2 = this.u;
        int iHashCode = (iG + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.v;
        int iHashCode2 = (iHashCode + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.w;
        int iHashCode3 = (iHashCode2 + (str4 == null ? 0 : str4.hashCode())) * 31;
        Boolean bool = this.x;
        return iHashCode3 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySet(id=");
        sb.append(this.b);
        sb.append(", timestamp=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", publishedTimestamp=");
        sb.append(this.e);
        sb.append(", user=");
        sb.append(this.f);
        sb.append(", wordLang=");
        sb.append(this.g);
        sb.append(", defLang=");
        sb.append(this.h);
        sb.append(", title=");
        sb.append(this.i);
        sb.append(", passwordUse=");
        sb.append(this.j);
        sb.append(", passwordEdit=");
        sb.append(this.k);
        sb.append(", accessType=");
        sb.append(this.l);
        sb.append(", accessCodePrefix=");
        sb.append(this.m);
        sb.append(", description=");
        sb.append(this.n);
        sb.append(", numTerms=");
        sb.append(this.o);
        sb.append(", hasImages=");
        sb.append(this.p);
        sb.append(", parentId=");
        sb.append(this.q);
        sb.append(", creationSource=");
        sb.append(this.r);
        sb.append(", privacyLockStatus=");
        sb.append(this.s);
        sb.append(", hasDiagrams=");
        sb.append(this.t);
        sb.append(", webUrl=");
        sb.append(this.u);
        sb.append(", thumbnailUrl=");
        sb.append(this.v);
        sb.append(", magicNoteUuid=");
        sb.append(this.w);
        sb.append(", isDeleted=");
        return a.k(sb, this.x, ")");
    }
}
