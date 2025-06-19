package com.snowplowanalytics.core.tracker;

import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class j extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ k b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(k kVar, int i) {
        super(0);
        this.a = i;
        this.b = kVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(this.b, "serviceProvider");
                return new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(5);
            case 1:
                k serviceProvider = this.b;
                Intrinsics.checkNotNullParameter(serviceProvider, "serviceProvider");
                com.snowplowanalytics.core.media.controller.a aVar = new com.snowplowanalytics.core.media.controller.a(serviceProvider);
                new LinkedHashMap();
                return aVar;
            default:
                k serviceProvider2 = this.b;
                Intrinsics.checkNotNullParameter(serviceProvider2, "serviceProvider");
                return new com.snowplowanalytics.core.media.controller.a(serviceProvider2);
        }
    }
}
