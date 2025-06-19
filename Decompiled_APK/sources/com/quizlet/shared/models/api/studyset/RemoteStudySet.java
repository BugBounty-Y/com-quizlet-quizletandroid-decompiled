package com.quizlet.shared.models.api.studyset;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteStudySet {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Long a;
    public final Long b;
    public final String c;
    public final String d;
    public final String e;
    public final Boolean f;
    public final Boolean g;
    public final Integer h;
    public final String i;
    public final String j;
    public final Integer k;
    public final Boolean l;
    public final Integer m;
    public final Integer n;
    public final Integer o;
    public final Boolean p;
    public final String q;
    public final String r;
    public final String s;
    public final Integer t;
    public final String u;
    public final Long v;
    public final Long w;
    public final Long x;
    public final Boolean y;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteStudySet$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteStudySet(int i, Long l, Long l2, String str, String str2, String str3, Boolean bool, Boolean bool2, Integer num, String str4, String str5, Integer num2, Boolean bool3, Integer num3, Integer num4, Integer num5, Boolean bool4, String str6, String str7, String str8, Integer num6, String str9, Long l3, Long l4, Long l5, Boolean bool5) {
        if (16777215 != (i & 16777215)) {
            AbstractC5047c0.k(i, 16777215, RemoteStudySet$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = l2;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = bool;
        this.g = bool2;
        this.h = num;
        this.i = str4;
        this.j = str5;
        this.k = num2;
        this.l = bool3;
        this.m = num3;
        this.n = num4;
        this.o = num5;
        this.p = bool4;
        this.q = str6;
        this.r = str7;
        this.s = str8;
        this.t = num6;
        this.u = str9;
        this.v = l3;
        this.w = l4;
        this.x = l5;
        if ((i & 16777216) == 0) {
            this.y = null;
        } else {
            this.y = bool5;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteStudySet)) {
            return false;
        }
        RemoteStudySet remoteStudySet = (RemoteStudySet) obj;
        return Intrinsics.b(this.a, remoteStudySet.a) && Intrinsics.b(this.b, remoteStudySet.b) && Intrinsics.b(this.c, remoteStudySet.c) && Intrinsics.b(this.d, remoteStudySet.d) && Intrinsics.b(this.e, remoteStudySet.e) && Intrinsics.b(this.f, remoteStudySet.f) && Intrinsics.b(this.g, remoteStudySet.g) && Intrinsics.b(this.h, remoteStudySet.h) && Intrinsics.b(this.i, remoteStudySet.i) && Intrinsics.b(this.j, remoteStudySet.j) && Intrinsics.b(this.k, remoteStudySet.k) && Intrinsics.b(this.l, remoteStudySet.l) && Intrinsics.b(this.m, remoteStudySet.m) && Intrinsics.b(this.n, remoteStudySet.n) && Intrinsics.b(this.o, remoteStudySet.o) && Intrinsics.b(this.p, remoteStudySet.p) && Intrinsics.b(this.q, remoteStudySet.q) && Intrinsics.b(this.r, remoteStudySet.r) && Intrinsics.b(this.s, remoteStudySet.s) && Intrinsics.b(this.t, remoteStudySet.t) && Intrinsics.b(this.u, remoteStudySet.u) && Intrinsics.b(this.v, remoteStudySet.v) && Intrinsics.b(this.w, remoteStudySet.w) && Intrinsics.b(this.x, remoteStudySet.x) && Intrinsics.b(this.y, remoteStudySet.y);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        Long l2 = this.b;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        String str = this.c;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode4 = (iHashCode3 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        int iHashCode5 = (iHashCode4 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Boolean bool = this.f;
        int iHashCode6 = (iHashCode5 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.g;
        int iHashCode7 = (iHashCode6 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Integer num = this.h;
        int iHashCode8 = (iHashCode7 + (num == null ? 0 : num.hashCode())) * 31;
        String str4 = this.i;
        int iHashCode9 = (iHashCode8 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.j;
        int iHashCode10 = (iHashCode9 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Integer num2 = this.k;
        int iHashCode11 = (iHashCode10 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Boolean bool3 = this.l;
        int iHashCode12 = (iHashCode11 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        Integer num3 = this.m;
        int iHashCode13 = (iHashCode12 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.n;
        int iHashCode14 = (iHashCode13 + (num4 == null ? 0 : num4.hashCode())) * 31;
        Integer num5 = this.o;
        int iHashCode15 = (iHashCode14 + (num5 == null ? 0 : num5.hashCode())) * 31;
        Boolean bool4 = this.p;
        int iHashCode16 = (iHashCode15 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
        String str6 = this.q;
        int iHashCode17 = (iHashCode16 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.r;
        int iHashCode18 = (iHashCode17 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.s;
        int iHashCode19 = (iHashCode18 + (str8 == null ? 0 : str8.hashCode())) * 31;
        Integer num6 = this.t;
        int iHashCode20 = (iHashCode19 + (num6 == null ? 0 : num6.hashCode())) * 31;
        String str9 = this.u;
        int iHashCode21 = (iHashCode20 + (str9 == null ? 0 : str9.hashCode())) * 31;
        Long l3 = this.v;
        int iHashCode22 = (iHashCode21 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.w;
        int iHashCode23 = (iHashCode22 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.x;
        int iHashCode24 = (iHashCode23 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Boolean bool5 = this.y;
        return iHashCode24 + (bool5 != null ? bool5.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteStudySet(id=");
        sb.append(this.a);
        sb.append(", creatorId=");
        sb.append(this.b);
        sb.append(", wordLang=");
        sb.append(this.c);
        sb.append(", defLang=");
        sb.append(this.d);
        sb.append(", title=");
        sb.append(this.e);
        sb.append(", passwordUse=");
        sb.append(this.f);
        sb.append(", passwordEdit=");
        sb.append(this.g);
        sb.append(", accessType=");
        sb.append(this.h);
        sb.append(", accessCodePrefix=");
        sb.append(this.i);
        sb.append(", description=");
        sb.append(this.j);
        sb.append(", numTerms=");
        sb.append(this.k);
        sb.append(", hasImages=");
        sb.append(this.l);
        sb.append(", parentId=");
        sb.append(this.m);
        sb.append(", creationSource=");
        sb.append(this.n);
        sb.append(", privacyLockStatus=");
        sb.append(this.o);
        sb.append(", hasDiagrams=");
        sb.append(this.p);
        sb.append(", webUrl=");
        sb.append(this.q);
        sb.append(", thumbnailUrl=");
        sb.append(this.r);
        sb.append(", price=");
        sb.append(this.s);
        sb.append(", purchasableType=");
        sb.append(this.t);
        sb.append(", magicNoteUuid=");
        sb.append(this.u);
        sb.append(", timestamp=");
        sb.append(this.v);
        sb.append(", lastModified=");
        sb.append(this.w);
        sb.append(", publishedTimestamp=");
        sb.append(this.x);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.y, ")");
    }
}
