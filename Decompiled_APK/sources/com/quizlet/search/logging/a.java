package com.quizlet.search.logging;

import com.quizlet.data.model.search.c;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.SearchBannerEventLog;
import com.quizlet.quizletandroid.ui.common.ads.G;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(c cVar, String action) {
        SearchBannerEventLog.Companion companion = SearchBannerEventLog.b;
        G payloadModifier = new G(cVar, 27);
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
        SearchBannerEventLog.Payload payload = new SearchBannerEventLog.Payload(null, null, null, 7, null);
        payloadModifier.invoke(payload);
        SearchBannerEventLog searchBannerEventLog = new SearchBannerEventLog(payload);
        searchBannerEventLog.setAction(action);
        this.a.l(searchBannerEventLog);
    }
}
