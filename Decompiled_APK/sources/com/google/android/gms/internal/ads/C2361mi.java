package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import androidx.camera.camera2.internal.C0148z;
import java.util.Set;
import java.util.WeakHashMap;

/* renamed from: com.google.android.gms.internal.ads.mi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2361mi extends AbstractC2863yB implements E5 {
    public final WeakHashMap c;
    public final Context d;
    public final Vp e;

    public C2361mi(Context context, Set set, Vp vp) {
        super(set);
        this.c = new WeakHashMap(1);
        this.d = context;
        this.e = vp;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final synchronized void R0(D5 d5) {
        j1(new Ts(d5, 18));
    }

    public final synchronized void k1(View view) {
        F5 f5;
        try {
            WeakHashMap weakHashMap = this.c;
            f5 = (F5) weakHashMap.get(view);
            if (f5 == null) {
                F5 f52 = new F5(this.d, view);
                f52.l.add(this);
                f52.c(3);
                weakHashMap.put(view, f52);
                f5 = f52;
            }
        } catch (Throwable th) {
            throw th;
        }
        if (this.e.X) {
            C2601s7 c2601s7 = AbstractC2773w7.s1;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                long jLongValue = ((Long) rVar.c.a(AbstractC2773w7.r1)).longValue();
                C0148z c0148z = f5.i;
                synchronized (c0148z.d) {
                    c0148z.b = jLongValue;
                }
                return;
            }
            throw th;
        }
        C0148z c0148z2 = f5.i;
        long j = F5.o;
        synchronized (c0148z2.d) {
            c0148z2.b = j;
        }
    }
}
