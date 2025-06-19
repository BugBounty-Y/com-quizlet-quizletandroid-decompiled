package com.google.android.play.core.review.internal;

import androidx.compose.foundation.text.input.internal.u;

/* loaded from: classes2.dex */
public final class g extends e {
    public final /* synthetic */ com.google.android.gms.tasks.f b;
    public final /* synthetic */ i c;
    public final /* synthetic */ j d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(j jVar, com.google.android.gms.tasks.f fVar, com.google.android.gms.tasks.f fVar2, i iVar) {
        super(fVar);
        this.b = fVar2;
        this.c = iVar;
        this.d = jVar;
    }

    @Override // com.google.android.play.core.review.internal.e
    public final void a() {
        synchronized (this.d.f) {
            try {
                j jVar = this.d;
                com.google.android.gms.tasks.f fVar = this.b;
                jVar.e.add(fVar);
                fVar.a.addOnCompleteListener(new u(jVar, false, fVar, 12));
                if (this.d.k.getAndIncrement() > 0) {
                    this.d.b.a("Already connected to the service.", new Object[0]);
                }
                j.b(this.d, this.c);
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
