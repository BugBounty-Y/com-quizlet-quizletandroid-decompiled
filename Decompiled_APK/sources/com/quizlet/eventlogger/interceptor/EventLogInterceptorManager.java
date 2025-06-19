package com.quizlet.eventlogger.interceptor;

import com.quizlet.eventlogger.model.EventLog;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class EventLogInterceptorManager {

    @NotNull
    private final List<IEventLogInterceptor> interceptors;

    public EventLogInterceptorManager(@FlipperEventLogInterceptor @NotNull IEventLogInterceptor flipperEventLogInterceptor) {
        Intrinsics.checkNotNullParameter(flipperEventLogInterceptor, "flipperEventLogInterceptor");
        this.interceptors = A.b(flipperEventLogInterceptor);
    }

    public final void a(EventLog eventLog) {
        Intrinsics.checkNotNullParameter(eventLog, "eventLog");
        c.a.a("%s action=%s", eventLog, eventLog.getAction());
        Iterator<T> it2 = this.interceptors.iterator();
        while (it2.hasNext()) {
            ((IEventLogInterceptor) it2.next()).a(eventLog);
        }
    }
}
