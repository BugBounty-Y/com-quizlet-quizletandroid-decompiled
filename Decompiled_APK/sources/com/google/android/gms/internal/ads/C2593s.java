package com.google.android.gms.internal.ads;

import android.content.Context;
import android.util.Pair;
import android.util.SparseArray;
import java.util.concurrent.CopyOnWriteArraySet;

/* renamed from: com.google.android.gms.internal.ads.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2593s {
    public final Context a;
    public final C2508q b;
    public final SparseArray c;
    public final boolean d;
    public final C2077g e;
    public final C1847ao f;
    public final CopyOnWriteArraySet g;
    public androidx.compose.ui.text.android.selection.f h = new androidx.compose.ui.text.android.selection.f(4, (byte) 0);
    public Bo i;
    public Pair j;
    public int k;
    public int l;
    public long m;
    public int n;

    public C2593s(com.amazon.aps.ads.privacy.a aVar) {
        this.a = (Context) aVar.c;
        C2508q c2508q = (C2508q) aVar.f;
        AbstractC1795We.p(c2508q);
        this.b = c2508q;
        this.c = new SparseArray();
        this.d = aVar.a;
        C1847ao c1847ao = (C1847ao) aVar.i;
        this.f = c1847ao;
        this.e = new C2077g((C2722v) aVar.d, c1847ao);
        this.g = new CopyOnWriteArraySet();
        new C1832aG(new EF());
        this.m = -9223372036854775807L;
        this.n = -1;
        this.l = 0;
    }
}
