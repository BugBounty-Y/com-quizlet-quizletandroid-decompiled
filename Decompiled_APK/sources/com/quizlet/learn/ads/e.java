package com.quizlet.learn.ads;

import com.google.android.gms.ads.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends com.google.android.gms.ads.d {
    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(l error) {
        Intrinsics.checkNotNullParameter(error, "error");
        timber.log.c.a.a("Learn AD failed to load with error (%s)", error);
    }
}
