package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3857a0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzr b;
    public final /* synthetic */ BinderC3869g0 c;

    public /* synthetic */ RunnableC3857a0(BinderC3869g0 binderC3869g0, zzr zzrVar, int i) {
        this.a = i;
        this.c = binderC3869g0;
        this.b = zzrVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws NumberFormatException {
        switch (this.a) {
            case 0:
                r1 r1Var = this.c.a;
                r1Var.j();
                r1Var.S(this.b);
                break;
            case 1:
                BinderC3869g0 binderC3869g0 = this.c;
                binderC3869g0.a.j();
                binderC3869g0.a.O(this.b);
                break;
            case 2:
                BinderC3869g0 binderC3869g02 = this.c;
                binderC3869g02.a.j();
                r1 r1Var2 = binderC3869g02.a;
                Z.l(r1Var2);
                zzr zzrVar = this.b;
                com.google.android.gms.common.internal.u.e(zzrVar.a);
                r1Var2.f0(zzrVar);
                break;
            default:
                BinderC3869g0 binderC3869g03 = this.c;
                binderC3869g03.a.j();
                r1 r1Var3 = binderC3869g03.a;
                Z.l(r1Var3);
                zzr zzrVar2 = this.b;
                com.google.android.gms.common.internal.u.e(zzrVar2.a);
                r1Var3.S(zzrVar2);
                r1Var3.R(zzrVar2);
                break;
        }
    }
}
