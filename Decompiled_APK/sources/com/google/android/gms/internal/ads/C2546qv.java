package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.qv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2546qv extends AbstractC2457os {
    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean A(AbstractC2674tv abstractC2674tv, C2631sv c2631sv, C2631sv c2631sv2) {
        synchronized (abstractC2674tv) {
            try {
                if (abstractC2674tv.c != c2631sv) {
                    return false;
                }
                abstractC2674tv.c = c2631sv2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2331lv f(AbstractC2460ov abstractC2460ov) {
        C2331lv c2331lv;
        C2331lv c2331lv2 = C2331lv.d;
        synchronized (abstractC2460ov) {
            try {
                c2331lv = abstractC2460ov.b;
                if (c2331lv != c2331lv2) {
                    abstractC2460ov.b = c2331lv2;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return c2331lv;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2631sv p(AbstractC2460ov abstractC2460ov) {
        C2631sv c2631sv;
        C2631sv c2631sv2 = C2631sv.c;
        synchronized (abstractC2460ov) {
            try {
                c2631sv = abstractC2460ov.c;
                if (c2631sv != c2631sv2) {
                    abstractC2460ov.c = c2631sv2;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return c2631sv;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void t(C2631sv c2631sv, C2631sv c2631sv2) {
        c2631sv.b = c2631sv2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void x(C2631sv c2631sv, Thread thread) {
        c2631sv.a = thread;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean y(AbstractC2460ov abstractC2460ov, C2331lv c2331lv, C2331lv c2331lv2) {
        synchronized (abstractC2460ov) {
            try {
                if (abstractC2460ov.b != c2331lv) {
                    return false;
                }
                abstractC2460ov.b = c2331lv2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean z(AbstractC2674tv abstractC2674tv, Object obj, Object obj2) {
        synchronized (abstractC2674tv) {
            try {
                if (abstractC2674tv.a != obj) {
                    return false;
                }
                abstractC2674tv.a = obj2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
