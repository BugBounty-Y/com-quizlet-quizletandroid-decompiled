package com.quizlet.ads.helper;

import com.google.android.gms.ads.d;
import com.google.android.gms.ads.l;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends d {
    public final /* synthetic */ Function1 b;

    public a(Function1 function1) {
        this.b = function1;
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(l error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.b.invoke(error);
    }
}
