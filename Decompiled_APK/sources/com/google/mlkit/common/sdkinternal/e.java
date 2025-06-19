package com.google.mlkit.common.sdkinternal;

import android.os.HandlerThread;
import android.os.Looper;
import com.google.android.gms.internal.ads.Ls;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final class e {
    public static final Object b = new Object();
    public static e c;
    public final Ls a;

    public e(Looper looper) {
        Ls ls = new Ls(looper, 5, false);
        Looper.getMainLooper();
        this.a = ls;
    }

    public static e a() {
        e eVar;
        synchronized (b) {
            try {
                if (c == null) {
                    HandlerThread handlerThread = new HandlerThread("MLHandler", 9);
                    handlerThread.start();
                    c = new e(handlerThread.getLooper());
                }
                eVar = c;
            } catch (Throwable th) {
                throw th;
            }
        }
        return eVar;
    }

    public static com.google.android.gms.tasks.m b(Callable callable) {
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        k.a.execute(new com.google.android.gms.tasks.k(callable, false, fVar, 3));
        return fVar.a;
    }
}
