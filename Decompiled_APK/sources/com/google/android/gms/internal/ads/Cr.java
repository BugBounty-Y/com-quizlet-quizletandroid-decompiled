package com.google.android.gms.internal.ads;

import java.util.Comparator;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Cr implements Comparator {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ Cr(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                Br br = (Br) obj;
                Br br2 = (Br) obj2;
                C2670tr c2670tr = (C2670tr) obj3;
                com.google.android.gms.ads.internal.client.s0 s0VarD = c2670tr.d(br2.a);
                double d = !(s0VarD instanceof Ug) ? 0.0d : ((Ug) s0VarD).j;
                com.google.android.gms.ads.internal.client.s0 s0VarD2 = c2670tr.d(br.a);
                int iCompare = Double.compare(d, s0VarD2 instanceof Ug ? ((Ug) s0VarD2).j : 0.0d);
                return iCompare == 0 ? Long.compare(br.b, br2.b) : iCompare;
            default:
                HashMap map = ME.a;
                LE le = (LE) obj3;
                return le.b(obj2) - le.b(obj);
        }
    }
}
