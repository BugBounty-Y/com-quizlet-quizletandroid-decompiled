package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.gj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2104gj implements Runnable {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ RunnableC2104gj() {
        this.a = 22;
    }

    private final void a() {
        Tm tm = (Tm) this.b;
        if (((Ys) tm.j) != null) {
            ((Gw) tm.d).c("Unbind from service.", new Object[0]);
            Context context = (Context) tm.b;
            ServiceConnectionC2372mt serviceConnectionC2372mt = (ServiceConnectionC2372mt) tm.i;
            serviceConnectionC2372mt.getClass();
            context.unbindService(serviceConnectionC2372mt);
            tm.a = false;
            tm.j = null;
            tm.i = null;
            ArrayList arrayList = (ArrayList) tm.f;
            synchronized (arrayList) {
                arrayList.clear();
            }
        }
    }

    private final void b() {
        JD jd = (JD) this.b;
        try {
            synchronized (jd) {
            }
            try {
                jd.a.c(jd.c, jd.d);
            } finally {
                jd.b(true);
            }
        } catch (zzik e) {
            AbstractC2096gb.A("ExoPlayerImplInternal", "Unexpected error delivering message on external thread.", e);
            throw new RuntimeException(e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:156:0x02ea A[Catch: all -> 0x02b9, TryCatch #5 {all -> 0x02b9, blocks: (B:134:0x02b0, B:136:0x02b4, B:141:0x02bc, B:147:0x02c7, B:149:0x02cb, B:151:0x02d1, B:153:0x02db, B:155:0x02e5, B:157:0x02f6, B:156:0x02ea, B:158:0x02f8, B:160:0x0306, B:162:0x030e), top: B:209:0x02b0 }] */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            Method dump skipped, instructions count: 1066
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.RunnableC2104gj.run():void");
    }

    public RunnableC2104gj(C1895bs c1895bs) {
        this.a = 17;
        this.b = c1895bs.e;
    }

    public /* synthetic */ RunnableC2104gj(C2436oD c2436oD, JD jd) {
        this.a = 24;
        this.b = jd;
    }

    public /* synthetic */ RunnableC2104gj(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
