package com.quizlet.ads;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g implements InterfaceC1250k {
    public NativeCustomFormatAd a;
    public AdManagerAdView b;

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        AdManagerAdView adManagerAdView = this.b;
        if (adManagerAdView != null) {
            adManagerAdView.pause();
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        AdManagerAdView adManagerAdView = this.b;
        if (adManagerAdView != null) {
            adManagerAdView.resume();
        }
    }
}
