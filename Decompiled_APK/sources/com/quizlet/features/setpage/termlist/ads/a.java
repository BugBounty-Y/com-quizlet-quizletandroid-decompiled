package com.quizlet.features.setpage.termlist.ads;

import com.google.android.gms.ads.admanager.AdManagerAdView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final AdManagerAdView a;

    public a(AdManagerAdView adView) {
        Intrinsics.checkNotNullParameter(adView, "adView");
        this.a = adView;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AdViewData(adView=" + this.a + ", isAdLoaded=true)";
    }
}
