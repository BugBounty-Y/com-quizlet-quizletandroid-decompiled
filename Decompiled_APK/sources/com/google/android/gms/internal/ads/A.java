package com.google.android.gms.internal.ads;

import com.comscore.streaming.ContentMediaFormat;

/* loaded from: classes2.dex */
public final /* synthetic */ class A implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Fi b;

    public /* synthetic */ A(Fi fi, long j, int i) {
        this.a = 1;
        this.b = fi;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Fi fi = this.b;
        switch (this.a) {
            case 0:
                String str = Yo.a;
                WD wd = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                wd.i(wd.l(), 1016, new TD(8));
                break;
            case 1:
                String str2 = Yo.a;
                WD wd2 = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                wd2.i(wd2.j((C2093gF) wd2.d.e), 1021, new C2047fD(29));
                break;
            case 2:
                String str3 = Yo.a;
                WD wd3 = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                wd3.i(wd3.l(), 1030, new C2047fD(16));
                break;
            case 3:
                String str4 = Yo.a;
                WD wd4 = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                wd4.i(wd4.l(), ContentMediaFormat.PARTIAL_CONTENT_PODCAST, new TD(6));
                break;
            default:
                String str5 = Yo.a;
                WD wd5 = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                wd5.i(wd5.l(), 1019, new C2047fD(24));
                break;
        }
    }

    public /* synthetic */ A(Fi fi, Object obj, int i) {
        this.a = i;
        this.b = fi;
    }

    public /* synthetic */ A(Fi fi, String str, long j, long j2) {
        this.a = 0;
        this.b = fi;
    }
}
