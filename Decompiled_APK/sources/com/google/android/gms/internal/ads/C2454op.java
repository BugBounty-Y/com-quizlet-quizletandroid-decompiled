package com.google.android.gms.internal.ads;

import android.content.Context;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.HashSet;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.op, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2454op {
    public final Context a;
    public final Executor b;
    public final C1765Re c;
    public final C2411np d;
    public final Ep e;
    public final VersionInfoParcel f;
    public final FrameLayout g;
    public final Uq h;
    public final C1979dq i;
    public com.google.common.util.concurrent.e j;

    public C2454op(Context context, Executor executor, C1765Re c1765Re, Ep ep, C2411np c2411np, C1979dq c1979dq, VersionInfoParcel versionInfoParcel) {
        this.a = context;
        this.b = executor;
        this.c = c1765Re;
        this.e = ep;
        this.d = c2411np;
        this.i = c1979dq;
        this.f = versionInfoParcel;
        this.g = new FrameLayout(context);
        this.h = c1765Re.c();
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0030  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean a(com.google.android.gms.ads.internal.client.zzm r10, java.lang.String r11, com.google.android.gms.internal.ads.AbstractC2096gb r12, com.google.android.gms.internal.ads.Rn r13) {
        /*
            Method dump skipped, instructions count: 325
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2454op.a(com.google.android.gms.ads.internal.client.zzm, java.lang.String, com.google.android.gms.internal.ads.gb, com.google.android.gms.internal.ads.Rn):boolean");
    }

    public final synchronized C1608n b(Cp cp) {
        C2368mp c2368mp = (C2368mp) cp;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h8)).booleanValue()) {
            Sg sg = new Sg();
            sg.a = this.a;
            sg.b = c2368mp.a;
            Sg sg2 = new Sg(sg);
            Yh yh = new Yh(0);
            C2411np c2411np = this.d;
            Executor executor = this.b;
            ((HashSet) yh.m).add(new C2318li(c2411np, executor));
            yh.p(c2411np, executor);
            Zh zh = new Zh(yh);
            C1608n c1608n = new C1608n(this.c.b);
            c1608n.e = sg2;
            c1608n.d = zh;
            return c1608n;
        }
        C2411np c2411np2 = this.d;
        C2411np c2411np3 = new C2411np(c2411np2.a);
        c2411np3.h = c2411np2;
        Yh yh2 = new Yh(0);
        Executor executor2 = this.b;
        yh2.m(c2411np3, executor2);
        ((HashSet) yh2.h).add(new C2318li(c2411np3, executor2));
        ((HashSet) yh2.o).add(new C2318li(c2411np3, executor2));
        ((HashSet) yh2.n).add(new C2318li(c2411np3, executor2));
        ((HashSet) yh2.m).add(new C2318li(c2411np3, executor2));
        yh2.p(c2411np3, executor2);
        yh2.p = c2411np3;
        Sg sg3 = new Sg();
        sg3.a = this.a;
        sg3.b = c2368mp.a;
        Sg sg4 = new Sg(sg3);
        Zh zh2 = new Zh(yh2);
        C1608n c1608n2 = new C1608n(this.c.b);
        c1608n2.e = sg4;
        c1608n2.d = zh2;
        return c1608n2;
    }
}
