package com.google.android.gms.internal.ads;

import com.comscore.streaming.ContentMediaFormat;

/* renamed from: com.google.android.gms.internal.ads.iE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2180iE implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Fp b;

    public /* synthetic */ RunnableC2180iE(Fp fp, int i, long j, long j2) {
        this.a = 2;
        this.b = fp;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Fp fp = this.b;
        switch (this.a) {
            case 0:
                String str = Yo.a;
                WD wd = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd.i(wd.l(), 1007, new C2047fD(8));
                break;
            case 1:
                String str2 = Yo.a;
                WD wd2 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd2.i(wd2.l(), 1010, new C2047fD(19));
                break;
            case 2:
                String str3 = Yo.a;
                WD wd3 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd3.i(wd3.l(), com.pubmatic.sdk.common.h.AD_EXPIRED, new C2047fD(17));
                break;
            case 3:
                String str4 = Yo.a;
                WD wd4 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd4.i(wd4.l(), 1031, new TD(3));
                break;
            case 4:
                String str5 = Yo.a;
                WD wd5 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd5.i(wd5.l(), 1032, new TD(9));
                break;
            case 5:
                String str6 = Yo.a;
                WD wd6 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd6.i(wd6.l(), 1029, new TD(7));
                break;
            case 6:
                String str7 = Yo.a;
                WD wd7 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd7.i(wd7.l(), ContentMediaFormat.FULL_CONTENT_PODCAST, new TD(10));
                break;
            case 7:
                String str8 = Yo.a;
                WD wd8 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd8.i(wd8.l(), 1008, new C2047fD(22));
                break;
            default:
                String str9 = Yo.a;
                WD wd9 = ((SurfaceHolderCallbackC2091gD) fp.c).a.r;
                wd9.i(wd9.l(), 1012, new C2047fD(10));
                break;
        }
    }

    public /* synthetic */ RunnableC2180iE(Fp fp, long j) {
        this.a = 1;
        this.b = fp;
    }

    public /* synthetic */ RunnableC2180iE(Fp fp, Object obj, int i) {
        this.a = i;
        this.b = fp;
    }

    public /* synthetic */ RunnableC2180iE(Fp fp, String str, long j, long j2) {
        this.a = 7;
        this.b = fp;
    }
}
