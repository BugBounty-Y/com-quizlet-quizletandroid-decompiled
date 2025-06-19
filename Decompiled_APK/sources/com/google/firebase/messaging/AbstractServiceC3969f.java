package com.google.firebase.messaging;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;
import androidx.camera.camera2.internal.C0143u;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.firebase.messaging.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractServiceC3969f extends Service {
    static final long MESSAGE_TIMEOUT_S = 20;
    private static final String TAG = "EnhancedIntentService";
    private Binder binder;
    final ExecutorService executor;
    private int lastStartId;
    private final Object lock;
    private int runningTasks;

    public AbstractServiceC3969f() {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue(), new com.android.billingclient.api.p("Firebase-Messaging-Intent-Handle", 2));
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        this.executor = Executors.unconfigurableExecutorService(threadPoolExecutor);
        this.lock = new Object();
        this.runningTasks = 0;
    }

    public static Task access$000(AbstractServiceC3969f abstractServiceC3969f, Intent intent) {
        if (abstractServiceC3969f.handleIntentOnMainThread(intent)) {
            return S3.i(null);
        }
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        abstractServiceC3969f.executor.execute(new com.facebook.login.E(abstractServiceC3969f, intent, fVar, 2));
        return fVar.a;
    }

    public final void a(Intent intent) {
        if (intent != null) {
            D.a(intent);
        }
        synchronized (this.lock) {
            try {
                int i = this.runningTasks - 1;
                this.runningTasks = i;
                if (i == 0) {
                    stopSelfResultHook(this.lastStartId);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public abstract Intent getStartCommandIntent(Intent intent);

    public abstract void handleIntent(Intent intent);

    public boolean handleIntentOnMainThread(Intent intent) {
        return false;
    }

    @Override // android.app.Service
    public final synchronized IBinder onBind(Intent intent) {
        try {
            Log.isLoggable(TAG, 3);
            if (this.binder == null) {
                this.binder = new E(new com.airbnb.lottie.network.c(this, 27));
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.binder;
    }

    @Override // android.app.Service
    public void onDestroy() {
        this.executor.shutdown();
        super.onDestroy();
    }

    @Override // android.app.Service
    public final int onStartCommand(Intent intent, int i, int i2) {
        com.google.android.gms.tasks.m mVarI;
        synchronized (this.lock) {
            this.lastStartId = i2;
            this.runningTasks++;
        }
        Intent startCommandIntent = getStartCommandIntent(intent);
        if (startCommandIntent == null) {
            a(intent);
            return 2;
        }
        if (handleIntentOnMainThread(startCommandIntent)) {
            mVarI = S3.i(null);
        } else {
            com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
            this.executor.execute(new com.facebook.login.E(this, startCommandIntent, fVar, 2));
            mVarI = fVar.a;
        }
        if (mVarI.k()) {
            a(intent);
            return 2;
        }
        mVarI.b(new androidx.arch.core.executor.a(1), new C0143u(23, this, intent));
        return 3;
    }

    public boolean stopSelfResultHook(int i) {
        return stopSelfResult(i);
    }
}
