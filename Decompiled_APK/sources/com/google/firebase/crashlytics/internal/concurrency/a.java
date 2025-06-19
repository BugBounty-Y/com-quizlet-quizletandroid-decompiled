package com.google.firebase.crashlytics.internal.concurrency;

import androidx.appcompat.app.Q;
import androidx.camera.camera2.internal.T;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.f;
import com.google.android.gms.tasks.m;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public abstract class a {
    public static final androidx.arch.core.executor.a a = new androidx.arch.core.executor.a(1);

    public static m a(Task task, Task task2) {
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c(24);
        f fVar = new f((Q) cVar.a);
        T t = new T(fVar, new AtomicBoolean(false), cVar, 12);
        androidx.arch.core.executor.a aVar = a;
        task.f(aVar, t);
        task2.f(aVar, t);
        return fVar.a;
    }
}
