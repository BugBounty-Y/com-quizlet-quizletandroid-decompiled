package com.perimeterx.mobile_sdk.api_data;

import android.os.Handler;
import android.os.Looper;
import androidx.camera.camera2.internal.RunnableC0131h;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class e {
    public static final ReentrantLock a = new ReentrantLock();
    public static f b = f.a;

    public static void a(f state) {
        Intrinsics.checkNotNullParameter(state, "state");
        ReentrantLock reentrantLock = a;
        reentrantLock.lock();
        f fVar = b;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(state, "state");
        if (state != f.a && (fVar != f.d || state != f.c)) {
            b = state;
            new Handler(Looper.getMainLooper()).post(new RunnableC0131h(20));
        }
        reentrantLock.unlock();
    }
}
