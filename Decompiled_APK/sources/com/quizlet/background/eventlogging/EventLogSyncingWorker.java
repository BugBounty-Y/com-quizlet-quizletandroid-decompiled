package com.quizlet.background.eventlogging;

import android.content.Context;
import androidx.work.C1446u;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.x;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.EventLogUploader;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class EventLogSyncingWorker extends Worker {
    public final EventLogBuilder e;
    public final EventLogUploader f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public EventLogSyncingWorker(@NotNull Context context, @NotNull WorkerParameters workerParams, @NotNull EventLogBuilder eventLogBuilder, @NotNull EventLogUploader eventLogUploader) {
        super(context, workerParams);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(workerParams, "workerParams");
        Intrinsics.checkNotNullParameter(eventLogBuilder, "eventLogBuilder");
        Intrinsics.checkNotNullParameter(eventLogUploader, "eventLogUploader");
        this.e = eventLogBuilder;
        this.f = eventLogUploader;
    }

    @Override // androidx.work.Worker
    public final x doWork() {
        x c1446u;
        String str;
        c.a.a("Attempting to sync log files [inside job]", new Object[0]);
        CountDownLatch countDownLatch = new CountDownLatch(1);
        this.e.n(new com.google.firebase.tracing.a(4, this, countDownLatch));
        if (countDownLatch.await(4000L, TimeUnit.MILLISECONDS)) {
            c1446u = x.a();
            str = "success(...)";
        } else {
            c1446u = new C1446u();
            str = "failure(...)";
        }
        Intrinsics.checkNotNullExpressionValue(c1446u, str);
        return c1446u;
    }
}
