package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.i0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4135i0 {
    public final String A;
    public final long B;
    public final boolean C;
    public final boolean D;
    public final boolean E;
    public final boolean F;
    public final String G;
    public final String H;
    public final boolean I;
    public final boolean J;
    public final long a;
    public final String b;
    public final long c;
    public final long d;
    public final int e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final String i;
    public final String j;
    public final long k;
    public final long l;
    public final long m;
    public final boolean n;
    public final int o;
    public final String p;
    public final String q;
    public final boolean r;
    public final boolean s;
    public final boolean t;
    public final boolean u;
    public final boolean v;
    public final boolean w;
    public final boolean x;
    public final boolean y;
    public final String z;

    public C4135i0(long j, String username, long j2, long j3, int i, boolean z, boolean z2, boolean z3, String imageURL, String str, long j4, long j5, long j6, boolean z4, int i2, String str2, String str3, boolean z5, boolean z6, boolean z7, boolean z8, boolean z9, boolean z10, boolean z11, boolean z12, String str4, String str5, long j7, boolean z13, boolean z14, boolean z15, boolean z16, String signupCountryCode, String countryCode) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(imageURL, "imageURL");
        Intrinsics.checkNotNullParameter(signupCountryCode, "signupCountryCode");
        Intrinsics.checkNotNullParameter(countryCode, "countryCode");
        this.a = j;
        this.b = username;
        this.c = j2;
        this.d = j3;
        this.e = i;
        this.f = z;
        this.g = z2;
        this.h = z3;
        this.i = imageURL;
        this.j = str;
        this.k = j4;
        this.l = j5;
        this.m = j6;
        this.n = z4;
        this.o = i2;
        this.p = str2;
        this.q = str3;
        this.r = z5;
        this.s = z6;
        this.t = z7;
        this.u = z8;
        this.v = z9;
        this.w = z10;
        this.x = z11;
        this.y = z12;
        this.z = str4;
        this.A = str5;
        this.B = j7;
        this.C = z13;
        this.D = z14;
        this.E = z15;
        this.F = z16;
        this.G = signupCountryCode;
        this.H = countryCode;
        this.I = i != 0;
        this.J = i == 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4135i0)) {
            return false;
        }
        C4135i0 c4135i0 = (C4135i0) obj;
        return this.a == c4135i0.a && Intrinsics.b(this.b, c4135i0.b) && this.c == c4135i0.c && this.d == c4135i0.d && this.e == c4135i0.e && this.f == c4135i0.f && this.g == c4135i0.g && this.h == c4135i0.h && Intrinsics.b(this.i, c4135i0.i) && Intrinsics.b(this.j, c4135i0.j) && this.k == c4135i0.k && this.l == c4135i0.l && this.m == c4135i0.m && this.n == c4135i0.n && this.o == c4135i0.o && Intrinsics.b(this.p, c4135i0.p) && Intrinsics.b(this.q, c4135i0.q) && this.r == c4135i0.r && this.s == c4135i0.s && this.t == c4135i0.t && this.u == c4135i0.u && this.v == c4135i0.v && this.w == c4135i0.w && this.x == c4135i0.x && this.y == c4135i0.y && Intrinsics.b(this.z, c4135i0.z) && Intrinsics.b(this.A, c4135i0.A) && this.B == c4135i0.B && this.C == c4135i0.C && this.D == c4135i0.D && this.E == c4135i0.E && this.F == c4135i0.F && Intrinsics.b(this.G, c4135i0.G) && Intrinsics.b(this.H, c4135i0.H);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.e, androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31), 31, this.f), 31, this.g), 31, this.h), 31, this.i);
        String str = this.j;
        int iB = androidx.compose.animation.d0.b(this.o, androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.k), 31, this.l), 31, this.m), 31, this.n), 31);
        String str2 = this.p;
        int iHashCode = (iB + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.q;
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g((iHashCode + (str3 == null ? 0 : str3.hashCode())) * 31, 31, this.r), 31, this.s), 31, this.t), 31, this.u), 31, this.v), 31, this.w), 31, this.x), 31, this.y);
        String str4 = this.z;
        int iHashCode2 = (iG + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.A;
        return this.H.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d((iHashCode2 + (str5 != null ? str5.hashCode() : 0)) * 31, 31, this.B), 31, this.C), 31, this.D), 31, this.E), 31, this.F), 31, this.G);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FullUser(id=");
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
