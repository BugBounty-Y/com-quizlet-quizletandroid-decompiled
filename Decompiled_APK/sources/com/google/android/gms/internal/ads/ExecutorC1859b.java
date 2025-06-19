package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Looper;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

/* renamed from: com.google.android.gms.internal.ads.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ExecutorC1859b implements Executor {
    public final /* synthetic */ int a;
    public final Object b;

    public ExecutorC1859b(ExecutorService executorService, TD td) {
        this.a = 0;
        this.b = executorService;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                ((ExecutorService) this.b).execute(runnable);
                return;
            default:
                if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
                    ((com.google.android.gms.ads.internal.util.B) this.b).post(runnable);
                    return;
                }
                try {
                    runnable.run();
                    return;
                } catch (Throwable th) {
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    Context context = com.google.android.gms.ads.internal.j.C.h.e;
                    if (context != null) {
                        try {
                            if (((Boolean) AbstractC2086g8.b.o()).booleanValue()) {
                                com.google.android.gms.common.util.c.a(context, th);
                            }
                        } catch (IllegalStateException unused) {
                        }
                    }
                    throw th;
                }
        }
    }

    public ExecutorC1859b() {
        this.a = 1;
        this.b = new com.google.android.gms.ads.internal.util.B(Looper.getMainLooper(), 0);
    }
}
