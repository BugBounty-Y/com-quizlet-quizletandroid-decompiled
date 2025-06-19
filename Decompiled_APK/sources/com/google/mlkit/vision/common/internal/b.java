package com.google.mlkit.vision.common.internal;

import androidx.appcompat.app.Q;
import androidx.lifecycle.A;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1238a0;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.measurement.internal.A0;
import com.google.android.gms.tasks.f;
import java.io.Closeable;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public abstract class b implements Closeable, I, AutoCloseable {
    public static final com.quizlet.data.repository.widget.b e = new com.quizlet.data.repository.widget.b("MobileVisionBase", "");
    public final AtomicBoolean a = new AtomicBoolean(false);
    public final com.google.mlkit.vision.barcode.internal.e b;
    public final com.google.firebase.platforminfo.c c;
    public final Executor d;

    public b(com.google.mlkit.vision.barcode.internal.e eVar, Executor executor) {
        this.b = eVar;
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c(24);
        this.c = cVar;
        this.d = executor;
        eVar.b.incrementAndGet();
        eVar.a(executor, e.a, (Q) cVar.a).o(d.a);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable, com.google.mlkit.vision.barcode.a
    @InterfaceC1238a0(A.ON_DESTROY)
    public synchronized void close() {
        boolean z = true;
        if (this.a.getAndSet(true)) {
            return;
        }
        this.c.j();
        com.google.mlkit.vision.barcode.internal.e eVar = this.b;
        Executor executor = this.d;
        if (eVar.b.get() <= 0) {
            z = false;
        }
        u.k(z);
        eVar.a.j(new A0(eVar, false, new f(), 11), executor);
    }
}
