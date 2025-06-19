package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import com.google.android.gms.ads.admanager.AdManagerAdView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final com.quizlet.ads.c a;
    public final AdManagerAdView b;
    public boolean c;

    public d(com.quizlet.ads.c adUnit, AdManagerAdView adView) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        Intrinsics.checkNotNullParameter(adView, "adView");
        this.a = adUnit;
        this.b = adView;
        this.c = false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b.equals(dVar.b) && this.c == dVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "AdViewData(adUnit=" + this.a + ", adView=" + this.b + ", isAdLoaded=" + this.c + ")";
    }
}
