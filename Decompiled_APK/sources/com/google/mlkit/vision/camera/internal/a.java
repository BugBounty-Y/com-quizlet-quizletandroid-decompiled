package com.google.mlkit.vision.camera.internal;

import androidx.camera.core.impl.utils.executor.h;
import com.google.android.gms.measurement.internal.A0;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class a implements Executor {
    public final h a;
    public final AtomicBoolean b = new AtomicBoolean();

    public a(h hVar) {
        this.a = hVar;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        if (this.b.get()) {
            return;
        }
        this.a.execute(new A0(this, false, runnable, 12));
    }
}
