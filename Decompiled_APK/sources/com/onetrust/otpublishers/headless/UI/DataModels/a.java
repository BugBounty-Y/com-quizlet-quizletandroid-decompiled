package com.onetrust.otpublishers.headless.UI.DataModels;

import androidx.compose.animation.d0;
import androidx.room.s;
import com.airbnb.lottie.animation.keyframe.q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final String b;
    public final boolean c;
    public final String d;
    public final boolean e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;
    public final boolean m;
    public final boolean n;
    public final String o;
    public final boolean p;
    public final String q;
    public final String r;
    public final String s;
    public final q t;
    public final s u;

    public a(String alertMoreInfoText, String str, boolean z, String bannerRejectAllButtonText, boolean z2, String str2, String str3, String str4, String str5, String str6, String str7, String str8, boolean z3, boolean z4, String bannerAdditionalDescPlacement, boolean z5, String str9, String bannerDPDTitle, String bannerDPDDescription, q otBannerUIProperty, s sVar) {
        Intrinsics.checkNotNullParameter(alertMoreInfoText, "alertMoreInfoText");
        Intrinsics.checkNotNullParameter(bannerRejectAllButtonText, "bannerRejectAllButtonText");
        Intrinsics.checkNotNullParameter(bannerAdditionalDescPlacement, "bannerAdditionalDescPlacement");
        Intrinsics.checkNotNullParameter(bannerDPDTitle, "bannerDPDTitle");
        Intrinsics.checkNotNullParameter(bannerDPDDescription, "bannerDPDDescription");
        Intrinsics.checkNotNullParameter(otBannerUIProperty, "otBannerUIProperty");
        this.a = alertMoreInfoText;
        this.b = str;
        this.c = z;
        this.d = bannerRejectAllButtonText;
        this.e = z2;
        this.f = str2;
        this.g = str3;
        this.h = str4;
        this.i = str5;
        this.j = str6;
        this.k = str7;
        this.l = str8;
        this.m = z3;
        this.n = z4;
        this.o = bannerAdditionalDescPlacement;
        this.p = z5;
        this.q = str9;
        this.r = bannerDPDTitle;
        this.s = bannerDPDDescription;
        this.t = otBannerUIProperty;
        this.u = sVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && Intrinsics.b(this.d, aVar.d) && this.e == aVar.e && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g) && Intrinsics.b(this.h, aVar.h) && Intrinsics.b(this.i, aVar.i) && Intrinsics.b(this.j, aVar.j) && Intrinsics.b(this.k, aVar.k) && Intrinsics.b(this.l, aVar.l) && this.m == aVar.m && this.n == aVar.n && Intrinsics.b(this.o, aVar.o) && this.p == aVar.p && Intrinsics.b(this.q, aVar.q) && Intrinsics.b(this.r, aVar.r) && Intrinsics.b(this.s, aVar.s) && Intrinsics.b(this.t, aVar.t) && Intrinsics.b(this.u, aVar.u);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        boolean z = this.c;
        int i = z;
        if (z != 0) {
            i = 1;
        }
        int iE = d0.e((iHashCode2 + i) * 31, 31, this.d);
        boolean z2 = this.e;
        int i2 = z2;
        if (z2 != 0) {
            i2 = 1;
        }
        int i3 = (iE + i2) * 31;
        String str2 = this.f;
        int iHashCode3 = (i3 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.g;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.h;
        int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.i;
        int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.j;
        int iHashCode7 = (iHashCode6 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.k;
        int iHashCode8 = (iHashCode7 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.l;
        int iHashCode9 = (iHashCode8 + (str8 == null ? 0 : str8.hashCode())) * 31;
        boolean z3 = this.m;
        int i4 = z3;
        if (z3 != 0) {
            i4 = 1;
        }
        int i5 = (iHashCode9 + i4) * 31;
        boolean z4 = this.n;
        int i6 = z4;
        if (z4 != 0) {
            i6 = 1;
        }
        int iE2 = d0.e((i5 + i6) * 31, 31, this.o);
        boolean z5 = this.p;
        int i7 = (iE2 + (z5 ? 1 : z5 ? 1 : 0)) * 31;
        String str9 = this.q;
        int iHashCode10 = (this.t.hashCode() + d0.e(d0.e((i7 + (str9 == null ? 0 : str9.hashCode())) * 31, 31, this.r), 31, this.s)) * 31;
        s sVar = this.u;
        return iHashCode10 + (sVar != null ? sVar.hashCode() : 0);
    }

    public final String toString() {
        return "BannerData(alertMoreInfoText=" + this.a + ", alertAllowCookiesText=" + this.b + ", bannerShowRejectAllButton=" + this.c + ", bannerRejectAllButtonText=" + this.d + ", bannerSettingButtonDisplayLink=" + this.e + ", bannerMPButtonColor=" + this.f + ", bannerMPButtonTextColor=" + this.g + ", textColor=" + this.h + ", buttonColor=" + this.i + ", buttonTextColor=" + this.j + ", backgroundColor=" + this.k + ", bannerLinksTextColor=" + this.l + ", showBannerAcceptButton=" + this.m + ", showBannerCookieSetting=" + this.n + ", bannerAdditionalDescPlacement=" + this.o + ", isIABEnabled=" + this.p + ", iABType=" + this.q + ", bannerDPDTitle=" + this.r + ", bannerDPDDescription=" + this.s + ", otBannerUIProperty=" + this.t + ", otGlobalUIProperty=" + this.u + ')';
    }
}
