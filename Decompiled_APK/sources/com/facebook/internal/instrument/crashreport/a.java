package com.facebook.internal.instrument.crashreport;

import com.google.android.gms.internal.mlkit_vision_common.E2;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import java.lang.Thread;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements Thread.UncaughtExceptionHandler {
    public static final h b = new h(8);
    public static a c;
    public final Thread.UncaughtExceptionHandler a;

    public a(Thread.UncaughtExceptionHandler uncaughtExceptionHandler) {
        this.a = uncaughtExceptionHandler;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread t, Throwable e) {
        Intrinsics.checkNotNullParameter(t, "t");
        Intrinsics.checkNotNullParameter(e, "e");
        if (e != null) {
            Throwable th = null;
            Throwable cause = e;
            loop0: while (true) {
                if (cause == null || cause == th) {
                    break;
                }
                StackTraceElement[] stackTrace = cause.getStackTrace();
                Intrinsics.checkNotNullExpressionValue(stackTrace, "t.stackTrace");
                for (StackTraceElement element : stackTrace) {
                    Intrinsics.checkNotNullExpressionValue(element, "element");
                    if (G2.e(element)) {
                        E2.b(e);
                        F2.c(e, com.facebook.internal.instrument.a.d).b();
                        break loop0;
                    }
                }
                th = cause;
                cause = cause.getCause();
            }
        }
        Thread.UncaughtExceptionHandler uncaughtExceptionHandler = this.a;
        if (uncaughtExceptionHandler != null) {
            uncaughtExceptionHandler.uncaughtException(t, e);
        }
    }
}
