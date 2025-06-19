package com.onetrust.otpublishers.headless.UI.DataModels;

import androidx.compose.animation.d0;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import androidx.webkit.internal.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class l {
    public final String a;
    public final com.onetrust.otpublishers.headless.UI.UIProperty.g b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final n i;
    public final String j;
    public final m k;
    public final String l;
    public final boolean m;
    public final androidx.compose.runtime.internal.j n;
    public final String o;
    public final String p;
    public final String q;
    public final String r;
    public final String s;
    public final p t;
    public final m u;
    public final com.onetrust.otpublishers.headless.UI.UIProperty.e v;
    public final String w;

    public l(String str, com.onetrust.otpublishers.headless.UI.UIProperty.g vendorListUIProperty, String str2, String str3, String str4, String str5, String str6, String str7, n confirmMyChoiceProperty, String str8, m vlTitleTextProperty, String str9, boolean z, androidx.compose.runtime.internal.j searchBarProperty, String str10, String str11, String str12, String str13, String str14, p vlPageHeaderTitle, m allowAllToggleTextProperty, com.onetrust.otpublishers.headless.UI.UIProperty.e eVar, String str15) {
        Intrinsics.checkNotNullParameter(vendorListUIProperty, "vendorListUIProperty");
        Intrinsics.checkNotNullParameter(confirmMyChoiceProperty, "confirmMyChoiceProperty");
        Intrinsics.checkNotNullParameter(vlTitleTextProperty, "vlTitleTextProperty");
        Intrinsics.checkNotNullParameter(searchBarProperty, "searchBarProperty");
        Intrinsics.checkNotNullParameter(vlPageHeaderTitle, "vlPageHeaderTitle");
        Intrinsics.checkNotNullParameter(allowAllToggleTextProperty, "allowAllToggleTextProperty");
        this.a = str;
        this.b = vendorListUIProperty;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = confirmMyChoiceProperty;
        this.j = str8;
        this.k = vlTitleTextProperty;
        this.l = str9;
        this.m = z;
        this.n = searchBarProperty;
        this.o = str10;
        this.p = str11;
        this.q = str12;
        this.r = str13;
        this.s = str14;
        this.t = vlPageHeaderTitle;
        this.u = allowAllToggleTextProperty;
        this.v = eVar;
        this.w = str15;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && Intrinsics.b(this.b, lVar.b) && Intrinsics.b(this.c, lVar.c) && Intrinsics.b(this.d, lVar.d) && Intrinsics.b(this.e, lVar.e) && Intrinsics.b(this.f, lVar.f) && Intrinsics.b(this.g, lVar.g) && Intrinsics.b(this.h, lVar.h) && Intrinsics.b(this.i, lVar.i) && Intrinsics.b(this.j, lVar.j) && Intrinsics.b(this.k, lVar.k) && Intrinsics.b(this.l, lVar.l) && this.m == lVar.m && Intrinsics.b(this.n, lVar.n) && Intrinsics.b(this.o, lVar.o) && Intrinsics.b(this.p, lVar.p) && Intrinsics.b(this.q, lVar.q) && Intrinsics.b(this.r, lVar.r) && Intrinsics.b(this.s, lVar.s) && Intrinsics.b(this.t, lVar.t) && Intrinsics.b(this.u, lVar.u) && Intrinsics.b(this.v, lVar.v) && Intrinsics.b(this.w, lVar.w);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int hashCode() {
        String str = this.a;
        int iHashCode = (this.b.hashCode() + ((str == null ? 0 : str.hashCode()) * 31)) * 31;
        String str2 = this.c;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.e;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.f;
        int iHashCode5 = (iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.g;
        int iHashCode6 = (iHashCode5 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.h;
        int iHashCode7 = (this.i.hashCode() + ((iHashCode6 + (str7 == null ? 0 : str7.hashCode())) * 31)) * 31;
        String str8 = this.j;
        int iHashCode8 = (this.k.hashCode() + ((iHashCode7 + (str8 == null ? 0 : str8.hashCode())) * 31)) * 31;
        String str9 = this.l;
        int iHashCode9 = (iHashCode8 + (str9 == null ? 0 : str9.hashCode())) * 31;
        boolean z = this.m;
        int i = z;
        if (z != 0) {
            i = 1;
        }
        int iHashCode10 = (this.n.hashCode() + ((iHashCode9 + i) * 31)) * 31;
        String str10 = this.o;
        int iHashCode11 = (iHashCode10 + (str10 == null ? 0 : str10.hashCode())) * 31;
        String str11 = this.p;
        int iHashCode12 = (iHashCode11 + (str11 == null ? 0 : str11.hashCode())) * 31;
        String str12 = this.q;
        int iHashCode13 = (iHashCode12 + (str12 == null ? 0 : str12.hashCode())) * 31;
        String str13 = this.r;
        int iHashCode14 = (iHashCode13 + (str13 == null ? 0 : str13.hashCode())) * 31;
        String str14 = this.s;
        int iHashCode15 = (this.u.hashCode() + ((this.t.hashCode() + ((iHashCode14 + (str14 == null ? 0 : str14.hashCode())) * 31)) * 31)) * 31;
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.v;
        int iHashCode16 = (iHashCode15 + (eVar == null ? 0 : eVar.hashCode())) * 31;
        String str15 = this.w;
        return iHashCode16 + (str15 != null ? str15.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("VendorListData(pcBackgroundColor=");
        sb.append(this.a);
        sb.append(", vendorListUIProperty=");
        sb.append(this.b);
        sb.append(", filterOnColor=");
        sb.append(this.c);
        sb.append(", filterOffColor=");
        sb.append(this.d);
        sb.append(", dividerColor=");
        sb.append(this.e);
        sb.append(", toggleTrackColor=");
        sb.append(this.f);
        sb.append(", toggleThumbOnColor=");
        sb.append(this.g);
        sb.append(", toggleThumbOffColor=");
        sb.append(this.h);
        sb.append(", confirmMyChoiceProperty=");
        sb.append(this.i);
        sb.append(", pcButtonTextColor=");
        sb.append(this.j);
        sb.append(", vlTitleTextProperty=");
        sb.append(this.k);
        sb.append(", pcTextColor=");
        sb.append(this.l);
        sb.append(", isGeneralVendorToggleEnabled=");
        sb.append(this.m);
        sb.append(", searchBarProperty=");
        sb.append(this.n);
        sb.append(", iabVendorsTitle=");
        sb.append(this.o);
        sb.append(", googleVendorsTitle=");
        sb.append(this.p);
        sb.append(", consentLabel=");
        sb.append(this.q);
        sb.append(", backButtonColor=");
        sb.append(this.r);
        sb.append(", pcButtonColor=");
        sb.append(this.s);
        sb.append(", vlPageHeaderTitle=");
        sb.append(this.t);
        sb.append(", allowAllToggleTextProperty=");
        sb.append(this.u);
        sb.append(", otPCUIProperty=");
        sb.append(this.v);
        sb.append(", rightChevronColor=");
        return d0.r(sb, this.w, ')');
    }
}
