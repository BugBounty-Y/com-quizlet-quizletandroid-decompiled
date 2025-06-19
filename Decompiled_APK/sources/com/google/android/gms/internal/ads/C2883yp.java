package com.google.android.gms.internal.ads;

import android.view.View;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.yp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2883yp implements Ep, Xh, Pv, Pk {
    public final /* synthetic */ int a;
    public Object b;

    public C2883yp(int i, byte b) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = new int[2];
                break;
        }
    }

    public static C2883yp e(C2501pt c2501pt) {
        return new C2883yp(new Lr(c2501pt, 2), 4);
    }

    public static C2883yp f(byte[] bArr) {
        return new C2883yp(C2604sA.a(bArr), 6);
    }

    public static C2883yp h(int i) {
        androidx.camera.core.impl.utils.executor.b bVar = AbstractC2463oy.a;
        byte[] bArr = new byte[i];
        ((SecureRandom) AbstractC2463oy.a.get()).nextBytes(bArr);
        return new C2883yp(C2604sA.a(bArr), 6);
    }

    public JSONObject a(View view) {
        if (view == null) {
            return AbstractC1938cs.a(0, 0, 0, 0);
        }
        int width = view.getWidth();
        int height = view.getHeight();
        int[] iArr = (int[]) this.b;
        view.getLocationOnScreen(iArr);
        return AbstractC1938cs.a(iArr[0], iArr[1], width, height);
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        switch (this.a) {
            case 1:
                Iq iq = (Iq) this.b;
                ((Mq) obj).r((Jq) iq.a, iq.b);
                break;
            case 8:
                WD wd = (WD) obj;
                C2816x7 c2816x7 = ((C2221jD) this.b).G;
                wd.i(wd.g(), 13, new C2047fD(11));
                break;
            case 9:
                ((SD) obj).a((IOException) this.b);
                break;
            default:
                C1740Nd c1740Nd = (C1740Nd) this.b;
                ((SD) obj).d(c1740Nd);
                int i = c1740Nd.a;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        ((Pq) this.b).zzi();
    }

    public void d(String str, HC hc) {
        AbstractC1981ds.g(hc, "provider");
        ((LinkedHashMap) this.b).put(str, hc);
    }

    public synchronized com.google.common.util.concurrent.e g(Fp fp, Dp dp, Qg qg) {
        C2831xg c2831xgZzb;
        try {
            if (qg != null) {
                this.b = qg;
            } else {
                this.b = (Qg) dp.h((Cp) fp.c).g();
            }
            c2831xgZzb = ((Qg) this.b).zzb();
        } catch (Throwable th) {
            throw th;
        }
        return c2831xgZzb.a(c2831xgZzb.b());
    }

    public EC i() {
        return new EC((LinkedHashMap) this.b);
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public Object j() {
        Qg qg;
        synchronized (this) {
            qg = (Qg) this.b;
        }
        return qg;
    }

    public List k(CharSequence charSequence) {
        charSequence.getClass();
        Iterator itE = ((At) this.b).e(this, charSequence);
        ArrayList arrayList = new ArrayList();
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return Collections.unmodifiableList(arrayList);
            }
            arrayList.add((String) abstractC2930zt.next());
        }
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* bridge */ /* synthetic */ com.google.common.util.concurrent.e q(Fp fp, Dp dp) {
        return g(fp, dp, null);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
    }

    public /* synthetic */ C2883yp(RD rd, C1740Nd c1740Nd) {
        this.a = 10;
        this.b = c1740Nd;
    }

    public /* synthetic */ C2883yp(RD rd, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) {
        this.a = 9;
        this.b = iOException;
    }

    public /* synthetic */ C2883yp(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public C2883yp(int i) {
        this.a = 7;
        this.b = AbstractC2543qs.o(i);
    }
}
