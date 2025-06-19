package com.quizlet.quizletandroid.ui.common.ads.prebid;

import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4942a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class e extends C4942a implements Function2 {
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        String p0 = (String) obj;
        String p1 = (String) obj2;
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        ((AdManagerAdRequest.Builder) this.a).addCustomTargeting(p0, p1);
        return Unit.a;
    }
}
