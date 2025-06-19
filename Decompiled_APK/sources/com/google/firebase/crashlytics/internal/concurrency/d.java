package com.google.firebase.crashlytics.internal.concurrency;

import android.util.Log;
import androidx.activity.K;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import java.util.concurrent.ExecutorService;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public static final c d = new c();
    public final b a;
    public final b b;
    public final b c;

    public d(ExecutorService backgroundExecutorService, ExecutorService blockingExecutorService) {
        Intrinsics.checkNotNullParameter(backgroundExecutorService, "backgroundExecutorService");
        Intrinsics.checkNotNullParameter(blockingExecutorService, "blockingExecutorService");
        this.a = new b(backgroundExecutorService);
        this.b = new b(backgroundExecutorService);
        S3.i(null);
        this.c = new b(blockingExecutorService);
    }

    public static final void a() {
        if (((Boolean) new K(0, d, c.class, "isBackgroundThread", "isBackgroundThread()Z", 0, 12).invoke()).booleanValue()) {
            return;
        }
        Thread.currentThread().getName();
        Log.isLoggable("FirebaseCrashlytics", 3);
    }

    public static final void b() {
        if (((Boolean) new K(0, d, c.class, "isBlockingThread", "isBlockingThread()Z", 0, 13).invoke()).booleanValue()) {
            return;
        }
        Thread.currentThread().getName();
        Log.isLoggable("FirebaseCrashlytics", 3);
    }
}
