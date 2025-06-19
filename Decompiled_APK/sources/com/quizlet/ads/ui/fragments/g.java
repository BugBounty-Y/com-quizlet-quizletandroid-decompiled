package com.quizlet.ads.ui.fragments;

import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g extends com.quizlet.uicommon.ui.common.text.a {
    public final /* synthetic */ StaticBannerAdFragment a;

    public g(StaticBannerAdFragment staticBannerAdFragment) {
        this.a = staticBannerAdFragment;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View widget) {
        Intrinsics.checkNotNullParameter(widget, "widget");
        String str = StaticBannerAdFragment.l;
        com.quizlet.ads.viewmodel.a aVar = (com.quizlet.ads.viewmodel.a) this.a.j.getValue();
        aVar.e.j(com.quizlet.ads.e.b);
    }
}
