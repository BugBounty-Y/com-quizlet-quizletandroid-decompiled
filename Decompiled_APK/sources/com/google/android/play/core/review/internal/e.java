package com.google.android.play.core.review.internal;

/* loaded from: classes2.dex */
public abstract class e implements Runnable {
    public final com.google.android.gms.tasks.f a;

    public e() {
        this.a = null;
    }

    public abstract void a();

    @Override // java.lang.Runnable
    public final void run() {
        try {
            a();
        } catch (Exception e) {
            com.google.android.gms.tasks.f fVar = this.a;
            if (fVar != null) {
                fVar.c(e);
            }
        }
    }

    public e(com.google.android.gms.tasks.f fVar) {
        this.a = fVar;
    }
}
