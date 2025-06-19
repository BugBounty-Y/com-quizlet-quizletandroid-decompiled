package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.HashMap;
import java.util.HashSet;

/* renamed from: com.google.android.gms.internal.ads.Ha, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C1701Ha {
    public int a = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int b = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int c = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int d = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int e = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public boolean g = true;
    public boolean h = true;
    public Bu i;
    public Bu j;
    public Bu k;
    public int l;
    public int m;
    public Bu n;
    public C2567ra o;
    public Bu p;
    public boolean q;
    public HashMap r;
    public HashSet s;

    public C1701Ha() {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        this.i = bu;
        this.j = bu;
        this.k = bu;
        this.l = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.m = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.n = bu;
        this.o = C2567ra.a;
        this.p = bu;
        this.q = true;
        this.r = new HashMap();
        this.s = new HashSet();
    }

    public final void a(PF pf) {
        this.a = pf.a;
        this.b = pf.b;
        this.c = pf.c;
        this.d = pf.d;
        this.e = pf.e;
        this.f = pf.f;
        this.g = pf.g;
        this.h = pf.h;
        this.i = pf.i;
        this.j = pf.j;
        this.k = pf.k;
        this.l = pf.l;
        this.m = pf.m;
        this.n = pf.n;
        this.o = pf.o;
        this.p = pf.p;
        this.q = pf.q;
        this.s = new HashSet(pf.s);
        this.r = new HashMap(pf.r);
    }
}
