package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.rg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2573rg implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.remote.model.notes.e b;

    public /* synthetic */ RunnableC2573rg(com.quizlet.remote.model.notes.e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.zza(new zzdwf(3));
                break;
            default:
                ((Ln) ((C2326lq) ((C2084g6) this.b.f).c).c).s();
                break;
        }
    }
}
