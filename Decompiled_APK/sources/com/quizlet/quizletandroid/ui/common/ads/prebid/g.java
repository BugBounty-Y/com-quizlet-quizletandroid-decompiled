package com.quizlet.quizletandroid.ui.common.ads.prebid;

import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

/* loaded from: classes3.dex */
public final class g {
    public final com.quizlet.data.interactor.course.a a;
    public final com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a b;
    public final AdManagerAdRequest.Builder c;
    public com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b d;
    public final u e;
    public final u f;

    public g(com.quizlet.data.interactor.course.a adManagerAdViewCreator, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a bannerAdUnitCreator, AdManagerAdRequest.Builder adManagerAdRequest) {
        Intrinsics.checkNotNullParameter(adManagerAdViewCreator, "adManagerAdViewCreator");
        Intrinsics.checkNotNullParameter(bannerAdUnitCreator, "bannerAdUnitCreator");
        Intrinsics.checkNotNullParameter(adManagerAdRequest, "adManagerAdRequest");
        this.a = adManagerAdViewCreator;
        this.b = bannerAdUnitCreator;
        this.c = adManagerAdRequest;
        this.e = kotlin.l.b(new a(this, 0));
        this.f = kotlin.l.b(new a(this, 1));
    }
}
