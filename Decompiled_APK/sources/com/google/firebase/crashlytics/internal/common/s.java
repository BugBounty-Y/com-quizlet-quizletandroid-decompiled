package com.google.firebase.crashlytics.internal.common;

import android.util.Log;
import java.lang.Thread;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class s implements Thread.UncaughtExceptionHandler {
    public final com.airbnb.lottie.network.d a;
    public final com.google.android.datatransport.cct.internal.s b;
    public final Thread.UncaughtExceptionHandler c;
    public final com.google.firebase.crashlytics.internal.a d;
    public final AtomicBoolean e = new AtomicBoolean(false);

    public s(com.airbnb.lottie.network.d dVar, com.google.android.datatransport.cct.internal.s sVar, Thread.UncaughtExceptionHandler uncaughtExceptionHandler, com.google.firebase.crashlytics.internal.a aVar) {
        this.a = dVar;
        this.b = sVar;
        this.c = uncaughtExceptionHandler;
        this.d = aVar;
    }

    public final boolean a(Thread thread, Throwable th) {
        if (thread == null) {
            Log.e("FirebaseCrashlytics", "Crashlytics will not record uncaught exception; null thread", null);
            return false;
        }
        if (th == null) {
            Log.e("FirebaseCrashlytics", "Crashlytics will not record uncaught exception; null throwable", null);
            return false;
        }
        if (!this.d.b()) {
            return true;
        }
        Log.isLoggable("FirebaseCrashlytics", 3);
        return false;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread thread, Throwable th) {
        Thread.UncaughtExceptionHandler uncaughtExceptionHandler = this.c;
        AtomicBoolean atomicBoolean = this.e;
        atomicBoolean.set(true);
        try {
            try {
                if (a(thread, th)) {
                    this.a.n(this.b, thread, th);
                } else {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                }
                if (uncaughtExceptionHandler != null) {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    uncaughtExceptionHandler.uncaughtException(thread, th);
                } else {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    System.exit(1);
                }
                atomicBoolean.set(false);
            } catch (Exception e) {
                Log.e("FirebaseCrashlytics", "An error occurred in the uncaught exception handler", e);
                if (uncaughtExceptionHandler != null) {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    uncaughtExceptionHandler.uncaughtException(thread, th);
                } else {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    System.exit(1);
                }
                atomicBoolean.set(false);
            }
        } catch (Throwable th2) {
            if (uncaughtExceptionHandler != null) {
                Log.isLoggable("FirebaseCrashlytics", 3);
                uncaughtExceptionHandler.uncaughtException(thread, th);
            } else {
                Log.isLoggable("FirebaseCrashlytics", 3);
                System.exit(1);
            }
            atomicBoolean.set(false);
            throw th2;
        }
    }
}
