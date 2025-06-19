package com.google.android.gms.tasks;

import com.google.android.gms.measurement.internal.A0;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class i implements l, d, c, b {
    public final /* synthetic */ int a;
    public final Executor b;
    public final a c;
    public final m d;

    public /* synthetic */ i(Executor executor, a aVar, m mVar, int i) {
        this.a = i;
        this.b = executor;
        this.c = aVar;
        this.d = mVar;
    }

    @Override // com.google.android.gms.tasks.l
    public final void a(Task task) {
        switch (this.a) {
            case 0:
                this.b.execute(new A0(6, this, task));
                break;
            default:
                this.b.execute(new androidx.camera.core.impl.utils.futures.h(this, false, task, 29));
                break;
        }
    }

    @Override // com.google.android.gms.tasks.b
    public void j() {
        this.d.s();
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        this.d.p(obj);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        this.d.r(exc);
    }
}
