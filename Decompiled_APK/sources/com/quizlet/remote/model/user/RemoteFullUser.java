package com.quizlet.remote.model.user;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFullUser {
    public final String A;
    public final Long B;
    public final Boolean C;
    public final Boolean D;
    public final Boolean E;
    public final Boolean F;
    public final String G;
    public final String H;
    public final long a;
    public final String b;
    public final Long c;
    public final Long d;
    public final Integer e;
    public final Boolean f;
    public final Boolean g;
    public final Boolean h;
    public final String i;
    public final String j;
    public final Long k;
    public final Long l;
    public final Long m;
    public final Boolean n;
    public final Integer o;
    public final String p;
    public final String q;
    public final Boolean r;
    public final Boolean s;
    public final Boolean t;
    public final Boolean u;
    public final Boolean v;
    public final Boolean w;
    public final Boolean x;
    public final Boolean y;
    public final String z;

    public RemoteFullUser(long j, String str, Long l, Long l2, @InterfaceC4853h(name = DBUserFields.Names.USER_UPGRADE_TYPE) Integer num, Boolean bool, Boolean bool2, Boolean bool3, @InterfaceC4853h(name = "_imageUrl") String str2, String str3, Long l3, Long l4, Long l5, Boolean bool4, Integer num2, @InterfaceC4853h(name = DBUserFields.Names.PROFILE_IMAGE_ID) String str4, String str5, @InterfaceC4853h(name = "_hasPassword") Boolean bool5, @InterfaceC4853h(name = "_hasFacebook") Boolean bool6, @InterfaceC4853h(name = "_hasGoogle") Boolean bool7, @InterfaceC4853h(name = "_isConfirmationRequired") Boolean bool8, @InterfaceC4853h(name = "_canChangeUsername") Boolean bool9, @InterfaceC4853h(name = "_isUnderAge") Boolean bool10, @InterfaceC4853h(name = "_isUnderAgeForAds") Boolean bool11, @InterfaceC4853h(name = "_needsChildDirectedTreatment") Boolean bool12, String str6, String str7, Long l6, Boolean bool13, @InterfaceC4853h(name = "_isEligibleForFreeTrial") Boolean bool14, @InterfaceC4853h(name = "_hasOptedIntoFreeOfflinePromo") Boolean bool15, @InterfaceC4853h(name = DBUserFields.Names.IS_SELF_LEARNER) Boolean bool16, String str8, String str9) {
        this.a = j;
        this.b = str;
        this.c = l;
        this.d = l2;
        this.e = num;
        this.f = bool;
        this.g = bool2;
        this.h = bool3;
        this.i = str2;
        this.j = str3;
        this.k = l3;
        this.l = l4;
        this.m = l5;
        this.n = bool4;
        this.o = num2;
        this.p = str4;
        this.q = str5;
        this.r = bool5;
        this.s = bool6;
        this.t = bool7;
        this.u = bool8;
        this.v = bool9;
        this.w = bool10;
        this.x = bool11;
        this.y = bool12;
        this.z = str6;
        this.A = str7;
        this.B = l6;
        this.C = bool13;
        this.D = bool14;
        this.E = bool15;
        this.F = bool16;
        this.G = str8;
        this.H = str9;
    }

    @NotNull
    public final RemoteFullUser copy(long j, String str, Long l, Long l2, @InterfaceC4853h(name = DBUserFields.Names.USER_UPGRADE_TYPE) Integer num, Boolean bool, Boolean bool2, Boolean bool3, @InterfaceC4853h(name = "_imageUrl") String str2, String str3, Long l3, Long l4, Long l5, Boolean bool4, Integer num2, @InterfaceC4853h(name = DBUserFields.Names.PROFILE_IMAGE_ID) String str4, String str5, @InterfaceC4853h(name = "_hasPassword") Boolean bool5, @InterfaceC4853h(name = "_hasFacebook") Boolean bool6, @InterfaceC4853h(name = "_hasGoogle") Boolean bool7, @InterfaceC4853h(name = "_isConfirmationRequired") Boolean bool8, @InterfaceC4853h(name = "_canChangeUsername") Boolean bool9, @InterfaceC4853h(name = "_isUnderAge") Boolean bool10, @InterfaceC4853h(name = "_isUnderAgeForAds") Boolean bool11, @InterfaceC4853h(name = "_needsChildDirectedTreatment") Boolean bool12, String str6, String str7, Long l6, Boolean bool13, @InterfaceC4853h(name = "_isEligibleForFreeTrial") Boolean bool14, @InterfaceC4853h(name = "_hasOptedIntoFreeOfflinePromo") Boolean bool15, @InterfaceC4853h(name = DBUserFields.Names.IS_SELF_LEARNER) Boolean bool16, String str8, String str9) {
        return new RemoteFullUser(j, str, l, l2, num, bool, bool2, bool3, str2, str3, l3, l4, l5, bool4, num2, str4, str5, bool5, bool6, bool7, bool8, bool9, bool10, bool11, bool12, str6, str7, l6, bool13, bool14, bool15, bool16, str8, str9);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFullUser)) {
            return false;
        }
        RemoteFullUser remoteFullUser = (RemoteFullUser) obj;
        return this.a == remoteFullUser.a && Intrinsics.b(this.b, remoteFullUser.b) && Intrinsics.b(this.c, remoteFullUser.c) && Intrinsics.b(this.d, remoteFullUser.d) && Intrinsics.b(this.e, remoteFullUser.e) && Intrinsics.b(this.f, remoteFullUser.f) && Intrinsics.b(this.g, remoteFullUser.g) && Intrinsics.b(this.h, remoteFullUser.h) && Intrinsics.b(this.i, remoteFullUser.i) && Intrinsics.b(this.j, remoteFullUser.j) && Intrinsics.b(this.k, remoteFullUser.k) && Intrinsics.b(this.l, remoteFullUser.l) && Intrinsics.b(this.m, remoteFullUser.m) && Intrinsics.b(this.n, remoteFullUser.n) && Intrinsics.b(this.o, remoteFullUser.o) && Intrinsics.b(this.p, remoteFullUser.p) && Intrinsics.b(this.q, remoteFullUser.q) && Intrinsics.b(this.r, remoteFullUser.r) && Intrinsics.b(this.s, remoteFullUser.s) && Intrinsics.b(this.t, remoteFullUser.t) && Intrinsics.b(this.u, remoteFullUser.u) && Intrinsics.b(this.v, remoteFullUser.v) && Intrinsics.b(this.w, remoteFullUser.w) && Intrinsics.b(this.x, remoteFullUser.x) && Intrinsics.b(this.y, remoteFullUser.y) && Intrinsics.b(this.z, remoteFullUser.z) && Intrinsics.b(this.A, remoteFullUser.A) && Intrinsics.b(this.B, remoteFullUser.B) && Intrinsics.b(this.C, remoteFullUser.C) && Intrinsics.b(this.D, remoteFullUser.D) && Intrinsics.b(this.E, remoteFullUser.E) && Intrinsics.b(this.F, remoteFullUser.F) && Intrinsics.b(this.G, remoteFullUser.G) && Intrinsics.b(this.H, remoteFullUser.H);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.c;
        int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.d;
        int iHashCode4 = (iHashCode3 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Integer num = this.e;
        int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
        Boolean bool = this.f;
        int iHashCode6 = (iHashCode5 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.g;
        int iHashCode7 = (iHashCode6 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Boolean bool3 = this.h;
        int iHashCode8 = (iHashCode7 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        String str2 = this.i;
        int iHashCode9 = (iHashCode8 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.j;
        int iHashCode10 = (iHashCode9 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Long l3 = this.k;
        int iHashCode11 = (iHashCode10 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.l;
        int iHashCode12 = (iHashCode11 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.m;
        int iHashCode13 = (iHashCode12 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Boolean bool4 = this.n;
        int iHashCode14 = (iHashCode13 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
        Integer num2 = this.o;
        int iHashCode15 = (iHashCode14 + (num2 == null ? 0 : num2.hashCode())) * 31;
        String str4 = this.p;
        int iHashCode16 = (iHashCode15 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.q;
        int iHashCode17 = (iHashCode16 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool5 = this.r;
        int iHashCode18 = (iHashCode17 + (bool5 == null ? 0 : bool5.hashCode())) * 31;
        Boolean bool6 = this.s;
        int iHashCode19 = (iHashCode18 + (bool6 == null ? 0 : bool6.hashCode())) * 31;
        Boolean bool7 = this.t;
        int iHashCode20 = (iHashCode19 + (bool7 == null ? 0 : bool7.hashCode())) * 31;
        Boolean bool8 = this.u;
        int iHashCode21 = (iHashCode20 + (bool8 == null ? 0 : bool8.hashCode())) * 31;
        Boolean bool9 = this.v;
        int iHashCode22 = (iHashCode21 + (bool9 == null ? 0 : bool9.hashCode())) * 31;
        Boolean bool10 = this.w;
        int iHashCode23 = (iHashCode22 + (bool10 == null ? 0 : bool10.hashCode())) * 31;
        Boolean bool11 = this.x;
        int iHashCode24 = (iHashCode23 + (bool11 == null ? 0 : bool11.hashCode())) * 31;
        Boolean bool12 = this.y;
        int iHashCode25 = (iHashCode24 + (bool12 == null ? 0 : bool12.hashCode())) * 31;
        String str6 = this.z;
        int iHashCode26 = (iHashCode25 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.A;
        int iHashCode27 = (iHashCode26 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Long l6 = this.B;
        int iHashCode28 = (iHashCode27 + (l6 == null ? 0 : l6.hashCode())) * 31;
        Boolean bool13 = this.C;
        int iHashCode29 = (iHashCode28 + (bool13 == null ? 0 : bool13.hashCode())) * 31;
        Boolean bool14 = this.D;
        int iHashCode30 = (iHashCode29 + (bool14 == null ? 0 : bool14.hashCode())) * 31;
        Boolean bool15 = this.E;
        int iHashCode31 = (iHashCode30 + (bool15 == null ? 0 : bool15.hashCode())) * 31;
        Boolean bool16 = this.F;
        int iHashCode32 = (iHashCode31 + (bool16 == null ? 0 : bool16.hashCode())) * 31;
        String str8 = this.G;
        int iHashCode33 = (iHashCode32 + (str8 == null ? 0 : str8.hashCode())) * 31;
        String str9 = this.H;
        return iHashCode33 + (str9 != null ? str9.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFullUser(id=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", timestamp=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", upgradeType=");
        sb.append(this.e);
        sb.append(", isVerified=");
        sb.append(this.f);
        sb.append(", isAdmin=");
        sb.append(this.g);
        sb.append(", isLocked=");
        sb.append(this.h);
        sb.append(", imageURL=");
        sb.append(this.i);
        sb.append(", timeZone=");
        sb.append(this.j);
        sb.append(", birthYear=");
        sb.append(this.k);
        sb.append(", birthMonth=");
        sb.append(this.l);
        sb.append(", birthDay=");
        sb.append(this.m);
        sb.append(", isConfirmed=");
        sb.append(this.n);
        sb.append(", selfIdentifiedTeacherStatus=");
        sb.append(this.o);
        sb.append(", profileImageID=");
        sb.append(this.p);
        sb.append(", email=");
        sb.append(this.q);
        sb.append(", hasPassword=");
        sb.append(this.r);
        sb.append(", hasFacebook=");
        sb.append(this.s);
        sb.append(", hasGoogle=");
        sb.append(this.t);
        sb.append(", isConfirmationRequired=");
        sb.append(this.u);
        sb.append(", canChangeUsername=");
        sb.append(this.v);
        sb.append(", isUnderAge=");
        sb.append(this.w);
        sb.append(", isUnderAgeForAds=");
        sb.append(this.x);
        sb.append(", needsChildDirectedTreatment=");
        sb.append(this.y);
        sb.append(", mobileLocale=");
        sb.append(this.z);
        sb.append(", userLocalePreference=");
        sb.append(this.A);
        sb.append(", srsNotificationTime=");
        sb.append(this.B);
        sb.append(", srsPushNotificationsEnabled=");
        sb.append(this.C);
        sb.append(", isEligibleForFreeTrial=");
        sb.append(this.D);
        sb.append(", hasOptedIntoFreeOfflinePromo=");
        sb.append(this.E);
        sb.append(", isSelfLearner=");
        sb.append(this.F);
        sb.append(", signupCountryCode=");
        sb.append(this.G);
        sb.append(", countryCode=");
        return android.support.v4.media.session.a.t(sb, this.H, ")");
    }
}
