package com.quizlet.quizletandroid.ui.common.ads;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I {
    public final com.google.android.material.shape.e a;
    public final C4641h b;
    public final C4641h c;
    public final com.quizlet.data.repository.searchexplanations.c d;

    public I(com.google.android.material.shape.e adNameCreator, C4641h pobBannerViewCreator, C4641h dfpBannerEventHandlerCreator, com.quizlet.data.repository.searchexplanations.c nearestAdSizeMapper) {
        Intrinsics.checkNotNullParameter(adNameCreator, "adNameCreator");
        Intrinsics.checkNotNullParameter(pobBannerViewCreator, "pobBannerViewCreator");
        Intrinsics.checkNotNullParameter(dfpBannerEventHandlerCreator, "dfpBannerEventHandlerCreator");
        Intrinsics.checkNotNullParameter(nearestAdSizeMapper, "nearestAdSizeMapper");
        this.a = adNameCreator;
        this.b = pobBannerViewCreator;
        this.c = dfpBannerEventHandlerCreator;
        this.d = nearestAdSizeMapper;
    }
}
