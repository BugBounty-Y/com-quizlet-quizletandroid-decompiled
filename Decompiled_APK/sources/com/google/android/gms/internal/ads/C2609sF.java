package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import androidx.camera.core.impl.C0186z;
import java.io.IOException;

/* renamed from: com.google.android.gms.internal.ads.sF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2609sF implements AF {
    public final int a;
    public final /* synthetic */ C2695uF b;

    public C2609sF(C2695uF c2695uF, int i) {
        this.b = c2695uF;
        this.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x005c  */
    @Override // com.google.android.gms.internal.ads.AF
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int a(long r14) throws android.os.RemoteException, java.io.IOException {
        /*
            r13 = this;
            com.google.android.gms.internal.ads.uF r0 = r13.b
            int r1 = r13.a
            boolean r2 = r0.B()
            r3 = 0
            if (r2 == 0) goto Lc
            return r3
        Lc:
            r0.x(r1)
            com.google.android.gms.internal.ads.zF[] r2 = r0.q
            r4 = r2[r1]
            boolean r2 = r0.K
            monitor-enter(r4)
            int r5 = r4.q     // Catch: java.lang.Throwable -> L4c
            r6 = r5
            int r5 = r4.i(r6)     // Catch: java.lang.Throwable -> L4c
            int r7 = r4.q     // Catch: java.lang.Throwable -> L4c
            int r8 = r4.n     // Catch: java.lang.Throwable -> L4c
            r10 = 1
            if (r7 == r8) goto L26
            r7 = r10
            goto L27
        L26:
            r7 = r3
        L27:
            if (r7 == 0) goto L4f
            long[] r7 = r4.l     // Catch: java.lang.Throwable -> L4c
            r11 = r7[r5]     // Catch: java.lang.Throwable -> L4c
            int r7 = (r14 > r11 ? 1 : (r14 == r11 ? 0 : -1))
            if (r7 >= 0) goto L32
            goto L4f
        L32:
            long r11 = r4.t     // Catch: java.lang.Throwable -> L4c
            int r7 = (r14 > r11 ? 1 : (r14 == r11 ? 0 : -1))
            if (r7 <= 0) goto L3e
            if (r2 != 0) goto L3b
            goto L3e
        L3b:
            int r8 = r8 - r6
            monitor-exit(r4)
            goto L51
        L3e:
            int r6 = r8 - r6
            r9 = 1
            r7 = r14
            int r8 = r4.h(r5, r6, r7, r9)     // Catch: java.lang.Throwable -> L4c
            r14 = -1
            monitor-exit(r4)
            if (r8 != r14) goto L51
        L4a:
            r8 = r3
            goto L51
        L4c:
            r0 = move-exception
            r14 = r0
            goto L73
        L4f:
            monitor-exit(r4)
            goto L4a
        L51:
            monitor-enter(r4)
            if (r8 < 0) goto L5c
            int r14 = r4.q     // Catch: java.lang.Throwable -> L5e
            int r14 = r14 + r8
            int r15 = r4.n     // Catch: java.lang.Throwable -> L5e
            if (r14 > r15) goto L5c
            goto L61
        L5c:
            r10 = r3
            goto L61
        L5e:
            r0 = move-exception
            r14 = r0
            goto L71
        L61:
            com.google.android.gms.internal.ads.AbstractC1795We.B(r10)     // Catch: java.lang.Throwable -> L5e
            int r14 = r4.q     // Catch: java.lang.Throwable -> L5e
            int r14 = r14 + r8
            r4.q = r14     // Catch: java.lang.Throwable -> L5e
            monitor-exit(r4)
            if (r8 != 0) goto L70
            r0.y(r1)
            return r3
        L70:
            return r8
        L71:
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L5e
            throw r14
        L73:
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L4c
            throw r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2609sF.a(long):int");
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final int b(Ps ps, MC mc, int i) throws RemoteException, IOException {
        int i2;
        boolean z;
        int i3;
        C2695uF c2695uF = this.b;
        int i4 = this.a;
        if (c2695uF.B()) {
            return -3;
        }
        c2695uF.x(i4);
        C2910zF c2910zF = c2695uF.q[i4];
        boolean z2 = c2695uF.K;
        c2910zF.getClass();
        boolean z3 = (i & 2) != 0;
        C0186z c0186z = c2910zF.b;
        synchronized (c2910zF) {
            try {
                mc.f = false;
                int i5 = c2910zF.q;
                i2 = -4;
                if (i5 != c2910zF.n) {
                    C1832aG c1832aG = ((C2867yF) c2910zF.c.c(c2910zF.o + i5)).a;
                    if (!z3 && c1832aG == c2910zF.f) {
                        int i6 = c2910zF.i(c2910zF.q);
                        if (c2910zF.A != null) {
                            int i7 = c2910zF.k[i6];
                            z = false;
                        } else {
                            z = true;
                        }
                        if (z) {
                            int i8 = c2910zF.k[i6];
                            mc.b = i8;
                            if (c2910zF.q == c2910zF.n - 1 && (z2 || c2910zF.u)) {
                                mc.b = 536870912 | i8;
                            }
                            mc.g = c2910zF.l[i6];
                            c0186z.b = c2910zF.j[i6];
                            c0186z.c = c2910zF.i[i6];
                            c0186z.d = c2910zF.m[i6];
                            i3 = -4;
                        } else {
                            mc.f = true;
                            i3 = -3;
                        }
                    }
                    c2910zF.k(c1832aG, ps);
                    i3 = -5;
                } else {
                    if (!z2 && !c2910zF.u) {
                        C1832aG c1832aG2 = c2910zF.x;
                        if (c1832aG2 == null || (!z3 && c1832aG2 == c2910zF.f)) {
                            i3 = -3;
                        }
                        c2910zF.k(c1832aG2, ps);
                        i3 = -5;
                    }
                    mc.b = 4;
                    mc.g = Long.MIN_VALUE;
                    i3 = -4;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (i3 != -4) {
            i2 = i3;
        } else if (!mc.s(4)) {
            int i9 = i & 1;
            if ((i & 4) == 0) {
                if (i9 != 0) {
                    C2824xF c2824xF = c2910zF.a;
                    C2824xF.i((androidx.compose.foundation.lazy.layout.p0) c2824xF.d, mc, c0186z, (Kn) c2824xF.b);
                } else {
                    C2824xF c2824xF2 = c2910zF.a;
                    c2824xF2.d = C2824xF.i((androidx.compose.foundation.lazy.layout.p0) c2824xF2.d, mc, c0186z, (Kn) c2824xF2.b);
                    c2910zF.q++;
                }
            } else if (i9 == 0) {
                c2910zF.q++;
            }
        }
        if (i2 == -3) {
            c2695uF.y(i4);
        }
        return i2;
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final void j() throws IOException {
        IOException iOException;
        C2695uF c2695uF = this.b;
        C2883yp c2883yp = c2695uF.q[this.a].A;
        if (c2883yp != null) {
            throw ((zzru) c2883yp.b);
        }
        int i = c2695uF.A == 7 ? 6 : 3;
        C2326lq c2326lq = c2695uF.i;
        IOException iOException2 = (IOException) c2326lq.d;
        if (iOException2 != null) {
            throw iOException2;
        }
        HandlerC2094gG handlerC2094gG = (HandlerC2094gG) c2326lq.c;
        if (handlerC2094gG != null && (iOException = handlerC2094gG.c) != null && handlerC2094gG.d > i) {
            throw iOException;
        }
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final boolean zze() {
        C2695uF c2695uF = this.b;
        return !c2695uF.B() && c2695uF.q[this.a].n(c2695uF.K);
    }
}
