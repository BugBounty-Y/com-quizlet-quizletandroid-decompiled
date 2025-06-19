package com.quizlet.search.ads;

import com.google.android.gms.ads.admanager.AdManagerAdView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final AdManagerAdView a;

    public b(AdManagerAdView adView) {
        Intrinsics.checkNotNullParameter(adView, "adView");
        this.a = adView;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return Intrinsics.b(this.a, ((b) obj).a);
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
