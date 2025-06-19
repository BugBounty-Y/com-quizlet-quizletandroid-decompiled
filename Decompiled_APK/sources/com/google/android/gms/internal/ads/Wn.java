package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class Wn implements Vo {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;

    public Wn(Context context, C2227jd c2227jd, C2023eq c2023eq, VersionInfoParcel versionInfoParcel) {
        this.a = 6;
        this.c = context;
        this.d = c2227jd;
        this.b = c2023eq;
        this.e = versionInfoParcel;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 3;
            case 1:
                return 7;
            case 2:
                return 1;
            case 3:
                return 17;
            case 4:
                return 22;
            case 5:
                return 26;
            case 6:
                return 53;
            default:
                return 35;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        C2196io c2196io;
        switch (this.a) {
            case 0:
                AbstractC2773w7.a((Context) this.c);
                return ((C2227jd) this.d).d(new Q4(this, 7));
            case 1:
                return AbstractC2025es.L(((C2796wo) this.d).zzb(), new C1804Yb(this, 3), AbstractC2270kd.g);
            case 2:
                C2601s7 c2601s7 = AbstractC2773w7.Eb;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
                C2238jo c2238jo = (C2238jo) this.e;
                if (zBooleanValue && (c2196io = c2238jo.b) != null) {
                    return AbstractC2025es.E(c2196io);
                }
                C2601s7 c2601s72 = AbstractC2773w7.u1;
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                if (AbstractC2543qs.i((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)) || (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue() && (c2238jo.a.get() || !((C1931cl) this.b).b))) {
                    return AbstractC2025es.E(new C2196io(new Bundle(), 0));
                }
                c2238jo.a.set(true);
                return ((C2227jd) this.d).d(new Q4(this, 9));
            case 3:
                return ((C2227jd) this.d).d(new Q4(this, 15));
            case 4:
                return ((C2227jd) this.d).d(new Q4(this, 19));
            case 5:
                return ((C2227jd) this.d).d(new Q4(this, 21));
            case 6:
                return ((C2227jd) this.d).d(new Q4(this, 23));
            default:
                return ((C2227jd) this.d).d(new Q4(this, 25));
        }
    }

    public /* synthetic */ Wn(C2227jd c2227jd, Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.d = c2227jd;
        this.c = obj;
        this.b = obj2;
        this.e = obj3;
    }

    public /* synthetic */ Wn(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.d = obj;
        this.b = obj2;
        this.c = obj3;
        this.e = obj4;
    }
}
