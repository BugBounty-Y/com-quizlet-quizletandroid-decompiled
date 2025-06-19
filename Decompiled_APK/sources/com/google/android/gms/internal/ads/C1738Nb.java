package com.google.android.gms.internal.ads;

import java.lang.Thread;

/* renamed from: com.google.android.gms.internal.ads.Nb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1738Nb implements Thread.UncaughtExceptionHandler {
    public final /* synthetic */ int a;
    public final /* synthetic */ Thread.UncaughtExceptionHandler b;
    public final /* synthetic */ C1744Ob c;

    public /* synthetic */ C1738Nb(C1744Ob c1744Ob, Thread.UncaughtExceptionHandler uncaughtExceptionHandler, int i) {
        this.a = i;
        this.b = uncaughtExceptionHandler;
        this.c = c1744Ob;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread thread, Throwable th) {
        Thread.UncaughtExceptionHandler uncaughtExceptionHandler;
        switch (this.a) {
            case 0:
                uncaughtExceptionHandler = this.b;
                try {
                    try {
                        this.c.g(th);
                    } finally {
                    }
                } catch (Throwable unused) {
                    com.google.android.gms.ads.internal.util.client.i.e("AdMob exception reporter failed reporting the exception.");
                }
                if (uncaughtExceptionHandler != null) {
                    uncaughtExceptionHandler.uncaughtException(thread, th);
                    return;
                }
                return;
            default:
                uncaughtExceptionHandler = this.b;
                try {
                    try {
                        this.c.g(th);
                    } finally {
                    }
                } catch (Throwable unused2) {
                    com.google.android.gms.ads.internal.util.client.i.e("AdMob exception reporter failed reporting the exception.");
                }
                if (uncaughtExceptionHandler != null) {
                    uncaughtExceptionHandler.uncaughtException(thread, th);
                    return;
                }
                return;
        }
    }
}
