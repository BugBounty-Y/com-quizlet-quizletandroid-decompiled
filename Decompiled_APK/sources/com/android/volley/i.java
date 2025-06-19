package com.android.volley;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.s0;
import com.google.android.gms.internal.ads.B3;
import com.google.android.gms.internal.ads.C2047fD;
import com.google.android.gms.internal.ads.C2221jD;
import com.google.android.gms.internal.ads.C2670tr;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Lr;
import com.google.android.gms.internal.ads.RD;
import com.google.android.gms.internal.ads.SurfaceHolderCallbackC2091gD;
import com.google.android.gms.internal.ads.Ug;
import com.google.android.gms.internal.ads.WD;
import com.google.android.gms.internal.ads.Yo;
import com.google.android.gms.measurement.internal.A0;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.L0;
import com.google.android.gms.measurement.internal.O0;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Y0;
import com.google.android.gms.measurement.internal.Z;

/* loaded from: classes.dex */
public final class i implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public i(C2670tr c2670tr, long j, s0 s0Var) {
        this.a = 3;
        this.b = j;
        this.c = s0Var;
        this.d = c2670tr;
    }

    @Override // java.lang.Runnable
    public final void run() {
        long j = this.b;
        Object obj = this.d;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                l lVar = (l) obj;
                lVar.mEventLog.a(j, (String) obj2);
                lVar.mEventLog.b(lVar.toString());
                break;
            case 1:
                String str = Yo.a;
                C2221jD c2221jD = ((SurfaceHolderCallbackC2091gD) ((Fi) obj2).c).a;
                WD wd = c2221jD.r;
                RD rdL = wd.l();
                wd.i(rdL, 26, new Lr(rdL, obj, j));
                if (c2221jD.I == obj) {
                    C2047fD c2047fD = new C2047fD(5);
                    com.amazon.aps.ads.privacy.a aVar = c2221jD.m;
                    aVar.d(26, c2047fD);
                    aVar.c();
                    break;
                }
                break;
            case 2:
                B3 b3 = (B3) obj;
                b3.a.a(j, (String) obj2);
                b3.a.b(b3.toString());
                break;
            case 3:
                C2670tr c2670tr = (C2670tr) obj;
                Fi fi = c2670tr.n;
                if (fi != null) {
                    s0 s0Var = (s0) obj2;
                    fi.z(null, "pano_ts", this.b, -1, -1, s0Var instanceof Ug ? ((Ug) s0Var).d : null, c2670tr.p);
                    break;
                }
                break;
            case 4:
                D0 d0 = (D0) obj2;
                if (!TextUtils.isEmpty(((Y) d0.b).n().Y())) {
                    I i = ((Y) d0.b).i;
                    Y.k(i);
                    i.l.f("Using developer consent only; google app id found");
                    break;
                } else {
                    d0.i0((Bundle) obj, 0, j);
                    break;
                }
            default:
                O0 o0 = (O0) obj;
                o0.X((L0) obj2, false, j);
                o0.f = null;
                Y0 y0E = Z.e((Y) o0.b);
                y0E.i0(new A0(2, y0E, str));
                break;
        }
    }

    public /* synthetic */ i(Object obj, Object obj2, long j, int i) {
        this.a = i;
        this.d = obj;
        this.c = obj2;
        this.b = j;
    }

    public /* synthetic */ i(Object obj, Object obj2, long j, int i, boolean z) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.b = j;
    }
}
