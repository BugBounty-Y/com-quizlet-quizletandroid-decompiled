package com.onetrust.otpublishers.headless.UI.DataModels;

import androidx.compose.animation.d0;
import androidx.navigation.internal.m;
import com.google.android.gms.internal.ads.Yh;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i {
    public final boolean a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final m k;
    public final m l;
    public final androidx.compose.runtime.internal.j m;
    public final m n;
    public final Yh o;
    public final com.onetrust.otpublishers.headless.UI.UIProperty.e p;

    public i(boolean z, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String consentLabel, m summaryTitle, m summaryDescription, androidx.compose.runtime.internal.j searchBarProperty, m allowAllToggleTextProperty, Yh otSdkListUIProperty, com.onetrust.otpublishers.headless.UI.UIProperty.e eVar) {
        Intrinsics.checkNotNullParameter(consentLabel, "consentLabel");
        Intrinsics.checkNotNullParameter(summaryTitle, "summaryTitle");
        Intrinsics.checkNotNullParameter(summaryDescription, "summaryDescription");
        Intrinsics.checkNotNullParameter(searchBarProperty, "searchBarProperty");
        Intrinsics.checkNotNullParameter(allowAllToggleTextProperty, "allowAllToggleTextProperty");
        Intrinsics.checkNotNullParameter(otSdkListUIProperty, "otSdkListUIProperty");
        this.a = z;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = str8;
        this.j = consentLabel;
        this.k = summaryTitle;
        this.l = summaryDescription;
        this.m = searchBarProperty;
        this.n = allowAllToggleTextProperty;
        this.o = otSdkListUIProperty;
        this.p = eVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(this.d, iVar.d) && Intrinsics.b(this.e, iVar.e) && Intrinsics.b(this.f, iVar.f) && Intrinsics.b(this.g, iVar.g) && Intrinsics.b(this.h, iVar.h) && Intrinsics.b(this.i, iVar.i) && Intrinsics.b(this.j, iVar.j) && Intrinsics.b(this.k, iVar.k) && Intrinsics.b(this.l, iVar.l) && Intrinsics.b(this.m, iVar.m) && Intrinsics.b(this.n, iVar.n) && Intrinsics.b(this.o, iVar.o) && Intrinsics.b(this.p, iVar.p);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v29 */
    /* JADX WARN: Type inference failed for: r0v30 */
    public final int hashCode() {
        boolean z = this.a;
        ?? r0 = z;
        if (z) {
            r0 = 1;
        }
        int i = r0 * 31;
        String str = this.b;
        int iHashCode = (i + (str == null ? 0 : str.hashCode())) * 31;
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
        int iHashCode7 = (iHashCode6 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.i;
        int iHashCode8 = (this.o.hashCode() + ((this.n.hashCode() + ((this.m.hashCode() + ((this.l.hashCode() + ((this.k.hashCode() + d0.e((iHashCode7 + (str8 == null ? 0 : str8.hashCode())) * 31, 31, this.j)) * 31)) * 31)) * 31)) * 31)) * 31;
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.p;
        return iHashCode8 + (eVar != null ? eVar.hashCode() : 0);
    }

    public final String toString() {
        return "SDKListData(showSdkDescription=" + this.a + ", backButtonColor=" + this.b + ", backgroundColor=" + this.c + ", filterOnColor=" + this.d + ", filterOffColor=" + this.e + ", dividerColor=" + this.f + ", toggleThumbColorOn=" + this.g + ", toggleThumbColorOff=" + this.h + ", toggleTrackColor=" + this.i + ", consentLabel=" + this.j + ", summaryTitle=" + this.k + ", summaryDescription=" + this.l + ", searchBarProperty=" + this.m + ", allowAllToggleTextProperty=" + this.n + ", otSdkListUIProperty=" + this.o + ", otPCUIProperty=" + this.p + ')';
    }
}
