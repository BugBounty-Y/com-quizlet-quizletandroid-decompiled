package com.quizlet.quizletandroid.ui.common.ads.prebid;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class n extends com.google.android.gms.ads.d {
    public final d0 b = e0.b(1, 1, null, 4);

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(com.google.android.gms.ads.l error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.b.h(new com.quizlet.data.model.ads.a(new Exception(error.b)));
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdLoaded() {
        this.b.h(com.quizlet.data.model.ads.b.a);
    }
}
