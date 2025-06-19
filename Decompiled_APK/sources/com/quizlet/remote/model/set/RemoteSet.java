package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSet {
    public final boolean A;
    public final Boolean B;
    public final long a;
    public final Integer b;
    public final Integer c;
    public final Integer d;
    public final Long e;
    public final String f;
    public final String g;
    public final String h;
    public final Boolean i;
    public final Boolean j;
    public final Integer k;
    public final String l;
    public final String m;
    public final Integer n;
    public final Boolean o;
    public final Integer p;
    public final Integer q;
    public final Integer r;
    public final Boolean s;
    public final String t;
    public final String u;
    public final String v;
    public final Integer w;
    public final Long x;
    public final boolean y;
    public final Long z;

    public RemoteSet(long j, Integer num, Integer num2, Integer num3, Long l, String str, String str2, String str3, Boolean bool, Boolean bool2, Integer num4, String str4, String str5, Integer num5, Boolean bool3, Integer num6, Integer num7, Integer num8, Boolean bool4, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = DBStudySetFields.Names.THUMBNAIL_URL) String str7, String str8, Integer num9, @InterfaceC4853h(name = "clientId") Long l2, boolean z, Long l3, boolean z2, Boolean bool5) {
        this.a = j;
        this.b = num;
        this.c = num2;
        this.d = num3;
        this.e = l;
        this.f = str;
        this.g = str2;
        this.h = str3;
        this.i = bool;
        this.j = bool2;
        this.k = num4;
        this.l = str4;
        this.m = str5;
        this.n = num5;
        this.o = bool3;
        this.p = num6;
        this.q = num7;
        this.r = num8;
        this.s = bool4;
        this.t = str6;
        this.u = str7;
        this.v = str8;
        this.w = num9;
        this.x = l2;
        this.y = z;
        this.z = l3;
        this.A = z2;
        this.B = bool5;
    }

    @NotNull
    public final RemoteSet copy(long j, Integer num, Integer num2, Integer num3, Long l, String str, String str2, String str3, Boolean bool, Boolean bool2, Integer num4, String str4, String str5, Integer num5, Boolean bool3, Integer num6, Integer num7, Integer num8, Boolean bool4, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = DBStudySetFields.Names.THUMBNAIL_URL) String str7, String str8, Integer num9, @InterfaceC4853h(name = "clientId") Long l2, boolean z, Long l3, boolean z2, Boolean bool5) {
        return new RemoteSet(j, num, num2, num3, l, str, str2, str3, bool, bool2, num4, str4, str5, num5, bool3, num6, num7, num8, bool4, str6, str7, str8, num9, l2, z, l3, z2, bool5);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSet)) {
            return false;
        }
        RemoteSet remoteSet = (RemoteSet) obj;
        return this.a == remoteSet.a && Intrinsics.b(this.b, remoteSet.b) && Intrinsics.b(this.c, remoteSet.c) && Intrinsics.b(this.d, remoteSet.d) && Intrinsics.b(this.e, remoteSet.e) && Intrinsics.b(this.f, remoteSet.f) && Intrinsics.b(this.g, remoteSet.g) && Intrinsics.b(this.h, remoteSet.h) && Intrinsics.b(this.i, remoteSet.i) && Intrinsics.b(this.j, remoteSet.j) && Intrinsics.b(this.k, remoteSet.k) && Intrinsics.b(this.l, remoteSet.l) && Intrinsics.b(this.m, remoteSet.m) && Intrinsics.b(this.n, remoteSet.n) && Intrinsics.b(this.o, remoteSet.o) && Intrinsics.b(this.p, remoteSet.p) && Intrinsics.b(this.q, remoteSet.q) && Intrinsics.b(this.r, remoteSet.r) && Intrinsics.b(this.s, remoteSet.s) && Intrinsics.b(this.t, remoteSet.t) && Intrinsics.b(this.u, remoteSet.u) && Intrinsics.b(this.v, remoteSet.v) && Intrinsics.b(this.w, remoteSet.w) && Intrinsics.b(this.x, remoteSet.x) && this.y == remoteSet.y && Intrinsics.b(this.z, remoteSet.z) && this.A == remoteSet.A && Intrinsics.b(this.B, remoteSet.B);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Integer num = this.b;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.c;
        int iHashCode3 = (iHashCode2 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.d;
        int iHashCode4 = (iHashCode3 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Long l = this.e;
        int iHashCode5 = (iHashCode4 + (l == null ? 0 : l.hashCode())) * 31;
        String str = this.f;
        int iHashCode6 = (iHashCode5 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iHashCode7 = (iHashCode6 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.h;
        int iHashCode8 = (iHashCode7 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Boolean bool = this.i;
        int iHashCode9 = (iHashCode8 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.j;
        int iHashCode10 = (iHashCode9 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Integer num4 = this.k;
        int iHashCode11 = (iHashCode10 + (num4 == null ? 0 : num4.hashCode())) * 31;
        String str4 = this.l;
        int iHashCode12 = (iHashCode11 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.m;
        int iHashCode13 = (iHashCode12 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Integer num5 = this.n;
        int iHashCode14 = (iHashCode13 + (num5 == null ? 0 : num5.hashCode())) * 31;
        Boolean bool3 = this.o;
        int iHashCode15 = (iHashCode14 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        Integer num6 = this.p;
        int iHashCode16 = (iHashCode15 + (num6 == null ? 0 : num6.hashCode())) * 31;
        Integer num7 = this.q;
        int iHashCode17 = (iHashCode16 + (num7 == null ? 0 : num7.hashCode())) * 31;
        Integer num8 = this.r;
        int iHashCode18 = (iHashCode17 + (num8 == null ? 0 : num8.hashCode())) * 31;
        Boolean bool4 = this.s;
        int iHashCode19 = (iHashCode18 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
        String str6 = this.t;
        int iHashCode20 = (iHashCode19 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.u;
        int iHashCode21 = (iHashCode20 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.v;
        int iHashCode22 = (iHashCode21 + (str8 == null ? 0 : str8.hashCode())) * 31;
        Integer num9 = this.w;
        int iHashCode23 = (iHashCode22 + (num9 == null ? 0 : num9.hashCode())) * 31;
        Long l2 = this.x;
        int iG = d0.g((iHashCode23 + (l2 == null ? 0 : l2.hashCode())) * 31, 31, this.y);
        Long l3 = this.z;
        int iG2 = d0.g((iG + (l3 == null ? 0 : l3.hashCode())) * 31, 31, this.A);
        Boolean bool5 = this.B;
        return iG2 + (bool5 != null ? bool5.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSet(id=");
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
        sb.append(", isEligibleForPracticeTests=");
        return assistantMode.refactored.a.k(sb, this.B, ")");
    }

    public /* synthetic */ RemoteSet(long j, Integer num, Integer num2, Integer num3, Long l, String str, String str2, String str3, Boolean bool, Boolean bool2, Integer num4, String str4, String str5, Integer num5, Boolean bool3, Integer num6, Integer num7, Integer num8, Boolean bool4, String str6, String str7, String str8, Integer num9, Long l2, boolean z, Long l3, boolean z2, Boolean bool5, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, num, num2, num3, l, str, str2, str3, bool, bool2, num4, str4, str5, num5, bool3, num6, num7, num8, bool4, str6, str7, str8, num9, l2, (i & 16777216) != 0 ? false : z, l3, (i & 67108864) != 0 ? false : z2, (i & 134217728) != 0 ? null : bool5);
    }
}
