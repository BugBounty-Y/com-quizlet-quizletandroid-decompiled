package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import androidx.lifecycle.w0;
import com.google.android.gms.internal.ads.Yh;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLog;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLogger;
import com.quizlet.quizletandroid.managers.deeplinks.l;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends w0 {
    public final l b;
    public final Yh c;
    public final DeepLinkEventLogger d;
    public final com.quizlet.infra.legacysyncengine.managers.d e;
    public final com.google.firebase.crashlytics.internal.settings.b f;
    public final s0 g;

    public i(l deepLinkResolver, Yh deepLinkLookupManager, DeepLinkEventLogger deepLinkEventLogger, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.google.firebase.crashlytics.internal.settings.b requireEmailConfirmationFeature) {
        Intrinsics.checkNotNullParameter(deepLinkResolver, "deepLinkResolver");
        Intrinsics.checkNotNullParameter(deepLinkLookupManager, "deepLinkLookupManager");
        Intrinsics.checkNotNullParameter(deepLinkEventLogger, "deepLinkEventLogger");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(requireEmailConfirmationFeature, "requireEmailConfirmationFeature");
        this.b = deepLinkResolver;
        this.c = deepLinkLookupManager;
        this.d = deepLinkEventLogger;
        this.e = loggedInUserManager;
        this.f = requireEmailConfirmationFeature;
        this.g = e0.c(null);
    }

    public final void A(com.quizlet.infra.androidcontracts.deeplink.a deeplink, String str, String str2, String str3) {
        Intrinsics.checkNotNullParameter(deeplink, "deeplink");
        String deepLinkType = deeplink.identity();
        DeepLinkEventLogger deepLinkEventLogger = this.d;
        deepLinkEventLogger.getClass();
        Intrinsics.checkNotNullParameter(deepLinkType, "deepLinkType");
        DeepLinkEventLog.Companion companion = DeepLinkEventLog.b;
        com.quizlet.eventlogger.features.deeplink.a aVar = new com.quizlet.eventlogger.features.deeplink.a(deepLinkType, str, str2, str3, 0);
        companion.getClass();
        deepLinkEventLogger.a(DeepLinkEventLog.Companion.a("deep_link_failed", aVar));
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        Object value = ((u) this.c.p).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).dispose();
    }
}
