package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class j2 extends Z0 {
    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean B(l2 l2Var, k2 k2Var, k2 k2Var2) {
        synchronized (l2Var) {
            try {
                if (l2Var.c != k2Var) {
                    return false;
                }
                l2Var.c = k2Var2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void j(k2 k2Var, k2 k2Var2) {
        k2Var.b = k2Var2;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void s(k2 k2Var, Thread thread) {
        k2Var.a = thread;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean u(l2 l2Var, A1 a1, A1 a12) {
        synchronized (l2Var) {
            try {
                if (l2Var.b != a1) {
                    return false;
                }
                l2Var.b = a12;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean w(l2 l2Var, Object obj, Object obj2) {
        synchronized (l2Var) {
            try {
                if (l2Var.a != obj) {
                    return false;
                }
                l2Var.a = obj2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
