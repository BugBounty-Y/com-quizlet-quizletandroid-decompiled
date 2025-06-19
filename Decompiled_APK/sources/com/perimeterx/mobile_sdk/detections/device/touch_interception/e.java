package com.perimeterx.mobile_sdk.detections.device.touch_interception;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Window;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.perimeterx.mobile_sdk.configurations.i;
import com.perimeterx.mobile_sdk.session.l;
import java.util.Timer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C4975b0;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class e implements Application.ActivityLifecycleCallbacks {
    public static l b;
    public static boolean c;
    public static Timer d;
    public static final kotlinx.coroutines.internal.d f;
    public static kotlinx.coroutines.channels.h g;
    public static final kotlinx.coroutines.sync.c h;
    public static final e a = new e();
    public static final com.quizlet.data.interactor.school.b e = new com.quizlet.data.interactor.school.b(14);

    static {
        ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(5);
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool, "newFixedThreadPool(...)");
        f = E.c(new C4975b0(executorServiceNewFixedThreadPool));
        h = kotlinx.coroutines.sync.d.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(android.view.MotionEvent r17, kotlin.coroutines.jvm.internal.c r18) {
        /*
            Method dump skipped, instructions count: 272
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.detections.device.touch_interception.e.a(android.view.MotionEvent, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static void b() {
        try {
            Timer timer = d;
            if (timer != null) {
                timer.cancel();
            }
        } catch (Exception unused) {
        }
        d = null;
        try {
            Timer timer2 = new Timer();
            d = timer2;
            b bVar = new b(0);
            String str = i.a;
            timer2.schedule(bVar, 30000L, 30000L);
        } catch (Exception unused2) {
            d = null;
        }
    }

    public static void c(f nextState) {
        int iOrdinal;
        com.quizlet.data.interactor.school.b bVar = e;
        f fVar = (f) bVar.b;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(nextState, "nextState");
        if (fVar == nextState) {
            return;
        }
        if (nextState != f.a && (iOrdinal = fVar.ordinal()) != 0) {
            if (iOrdinal != 1) {
                if (iOrdinal != 2 && iOrdinal != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                return;
            } else {
                int iOrdinal2 = nextState.ordinal();
                if (iOrdinal2 != 0) {
                    if (iOrdinal2 == 1) {
                        return;
                    }
                    if (iOrdinal2 != 2 && iOrdinal2 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                }
            }
        }
        int iOrdinal3 = nextState.ordinal();
        if (iOrdinal3 != 0) {
            if (iOrdinal3 == 1) {
                new Handler(Looper.getMainLooper()).post(new RunnableC0131h(23));
            } else if (iOrdinal3 == 2) {
                new Handler(Looper.getMainLooper()).post(new RunnableC0131h(22));
            } else {
                if (iOrdinal3 != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                new Handler(Looper.getMainLooper()).post(new RunnableC0131h(21));
            }
        }
        Intrinsics.checkNotNullParameter(nextState, "<set-?>");
        bVar.b = nextState;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity p0, Bundle bundle) {
        Intrinsics.checkNotNullParameter(p0, "p0");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity p0, Bundle p1) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Window window = p0.getWindow();
        Window.Callback callback = window.getCallback();
        Intrinsics.d(callback);
        window.setCallback(new h(callback));
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        Window window = p0.getWindow();
        Window.Callback callback = window.getCallback();
        if (callback instanceof h) {
            window.setCallback(((h) callback).a);
        }
    }
}
