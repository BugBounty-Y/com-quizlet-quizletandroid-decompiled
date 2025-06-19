package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.UUID;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Ni implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;

    public /* synthetic */ Ni(C1741Ne c1741Ne, int i) {
        this.a = i;
        this.b = c1741Ne;
    }

    public Yn a() {
        VersionInfoParcel versionInfoParcelB = this.b.b();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Yn(versionInfoParcelB, c2227jd);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                VersionInfoParcel versionInfoParcelB = this.b.b();
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                return new C5(UUID.randomUUID().toString(), versionInfoParcelB, com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE, new JSONObject(), true);
            default:
                return a();
        }
    }
}
