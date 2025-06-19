package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3801h0 extends Z0 {
    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean A(AbstractC3816m0 abstractC3816m0, C3792e0 c3792e0, C3792e0 c3792e02) {
        synchronized (abstractC3816m0) {
            try {
                if (abstractC3816m0.b != c3792e0) {
                    return false;
                }
                abstractC3816m0.b = c3792e02;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean E(AbstractC3816m0 abstractC3816m0, Object obj, Object obj2) {
        synchronized (abstractC3816m0) {
            try {
                if (abstractC3816m0.a != obj) {
                    return false;
                }
                abstractC3816m0.a = obj2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean G(AbstractC3816m0 abstractC3816m0, C3813l0 c3813l0, C3813l0 c3813l02) {
        synchronized (abstractC3816m0) {
            try {
                if (abstractC3816m0.c != c3813l0) {
                    return false;
                }
                abstractC3816m0.c = c3813l02;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3792e0 e(AbstractC3816m0 abstractC3816m0) {
        C3792e0 c3792e0;
        C3792e0 c3792e02 = C3792e0.d;
        synchronized (abstractC3816m0) {
            c3792e0 = abstractC3816m0.b;
            if (c3792e0 != c3792e02) {
                abstractC3816m0.b = c3792e02;
            }
        }
        return c3792e0;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3813l0 p(AbstractC3816m0 abstractC3816m0) {
        C3813l0 c3813l0;
        C3813l0 c3813l02 = C3813l0.c;
        synchronized (abstractC3816m0) {
            c3813l0 = abstractC3816m0.c;
            if (c3813l0 != c3813l02) {
                abstractC3816m0.c = c3813l02;
            }
        }
        return c3813l0;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void t(C3813l0 c3813l0, C3813l0 c3813l02) {
        c3813l0.b = c3813l02;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void v(C3813l0 c3813l0, Thread thread) {
        c3813l0.a = thread;
    }
}
