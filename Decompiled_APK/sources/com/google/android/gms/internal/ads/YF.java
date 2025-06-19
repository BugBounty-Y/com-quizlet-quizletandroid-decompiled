package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import android.util.SparseIntArray;
import androidx.compose.material3.C0591b1;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class YF implements InterfaceC2037f3 {
    public int a;
    public final Object b;
    public final Object c;
    public final Object d;
    public Object e;

    public YF(C2034f0 c2034f0, C2881yn c2881yn, byte[] bArr, androidx.camera.camera2.internal.compat.workaround.e[] eVarArr, int i) {
        this.b = c2034f0;
        this.c = c2881yn;
        this.d = bArr;
        this.e = eVarArr;
        this.a = i;
    }

    public boolean a(YF yf, int i) {
        return yf != null && Objects.equals(((MD[]) this.b)[i], ((MD[]) yf.b)[i]) && Objects.equals(((XF[]) this.c)[i], ((XF[]) yf.c)[i]);
    }

    public boolean b(int i) {
        return ((MD[]) this.b)[i] != null;
    }

    public synchronized void c() {
        C2711up c2711up;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j6)).booleanValue() && !com.google.android.gms.ads.internal.j.C.h.d().n().j) {
            ((ArrayDeque) this.d).clear();
            return;
        }
        synchronized (this) {
            try {
                if (((Or) this.e) == null) {
                    while (true) {
                        ArrayDeque arrayDeque = (ArrayDeque) this.d;
                        if (arrayDeque.isEmpty()) {
                            break;
                        }
                        c2711up = (C2711up) arrayDeque.pollFirst();
                        if (c2711up == null) {
                            break;
                        }
                        InterfaceC2798wq interfaceC2798wq = c2711up.g;
                        if (interfaceC2798wq != null) {
                            C2326lq c2326lq = (C2326lq) this.b;
                            synchronized (c2326lq) {
                                C2583rq c2583rq = (C2583rq) ((ConcurrentHashMap) c2326lq.b).get(interfaceC2798wq);
                                if (c2583rq == null) {
                                    break;
                                }
                                zzfej zzfejVar = (zzfej) c2326lq.c;
                                c2583rq.a();
                                if (c2583rq.a.size() < zzfejVar.e) {
                                    break;
                                }
                            }
                        }
                    }
                    Or or = new Or((C2326lq) this.b, (Os) this.c, c2711up);
                    this.e = or;
                    Fi fi = new Fi(this, false, c2711up, 25);
                    synchronized (or) {
                        C2846xv c2846xvN = AbstractC2025es.N((C2028ev) or.d, new C2487pf(13), c2711up.e);
                        c2846xvN.a(new Qv(0, c2846xvN, fi), c2711up.e);
                    }
                }
            } finally {
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0209  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x032d  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x01c4  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void d(com.google.android.gms.internal.ads.Kn r32) {
        /*
            Method dump skipped, instructions count: 920
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.YF.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    public void e(Eo eo, W w, C0591b1 c0591b1) {
    }

    public YF(C2125h3 c2125h3, int i) {
        this.e = c2125h3;
        this.b = new C2466p0(5, new byte[5]);
        this.c = new SparseArray();
        this.d = new SparseIntArray();
        this.a = i;
    }

    public YF(C2326lq c2326lq, C2498pq c2498pq, Os os) {
        this.a = 1;
        this.b = c2326lq;
        this.c = os;
        this.d = new ArrayDeque();
        c2498pq.a = new Os(this, 29);
    }

    public YF(MD[] mdArr, XF[] xfArr, C2697ub c2697ub, com.quizlet.data.repository.folderwithcreatorinclass.e eVar) {
        int length = mdArr.length;
        AbstractC1795We.B(length == xfArr.length);
        this.b = mdArr;
        this.c = (XF[]) xfArr.clone();
        this.d = c2697ub;
        this.e = eVar;
        this.a = length;
    }
}
