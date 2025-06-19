package com.quizlet.openwrap;

import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.openwrap.banner.c;
import com.pubmatic.sdk.openwrap.core.f;
import com.pubmatic.sdk.openwrap.core.k;
import com.quizlet.data.model.ads.d;
import com.quizlet.data.model.ads.e;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class b extends c.a implements k {
    public final d0 a = e0.b(1, 1, null, 4);

    @Override // com.pubmatic.sdk.openwrap.banner.c.a
    public final void onAdFailed(c p0, h p1) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        this.a.h(new com.quizlet.data.model.ads.a(new OpenWrapException(p1)));
    }

    @Override // com.pubmatic.sdk.openwrap.banner.c.a
    public final void onAdReceived(c p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        this.a.h(com.quizlet.data.model.ads.b.a);
    }

    @Override // com.pubmatic.sdk.openwrap.core.k
    public final void onBidFailed(com.pubmatic.sdk.openwrap.core.h p0, h p1) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        this.a.h(new d(new OpenWrapException(p1)));
    }

    @Override // com.pubmatic.sdk.openwrap.core.k
    public final void onBidReceived(com.pubmatic.sdk.openwrap.core.h p0, f p1) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        this.a.h(e.a);
    }
}
