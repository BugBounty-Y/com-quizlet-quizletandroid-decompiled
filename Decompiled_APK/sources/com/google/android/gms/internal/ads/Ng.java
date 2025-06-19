package com.google.android.gms.internal.ads;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class Ng implements Callable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Iq b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ Ng(androidx.camera.core.processing.e eVar, Iq iq, Bundle bundle) {
        this.c = eVar;
        this.b = iq;
        this.d = bundle;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        Bundle bundle;
        switch (this.a) {
            case 0:
                Og og = (Og) this.b.c.get();
                Bundle bundle2 = og.a;
                androidx.camera.core.processing.e eVar = (androidx.camera.core.processing.e) this.c;
                String str = (String) ((com.google.common.util.concurrent.e) ((InterfaceC2907zC) eVar.h).zzb()).get();
                boolean z = false;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.V6)).booleanValue() && ((com.google.android.gms.ads.internal.util.C) eVar.k).k()) {
                    z = true;
                }
                return new zzbvl(bundle2, (VersionInfoParcel) eVar.d, (ApplicationInfo) eVar.e, (String) eVar.f, (ArrayList) eVar.g, (PackageInfo) eVar.b, str, (String) eVar.i, null, null, z, ((C2023eq) eVar.l).a(), (Bundle) this.d, og.b, eVar.a);
            default:
                C1810Zb c1810Zb = (C1810Zb) this.b.c.get();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && (bundle = ((zzbvl) this.c).m) != null) {
                    bundle.putLong("get-ad-dictionary-sdkcore-start", c1810Zb.j);
                    bundle.putLong("get-ad-dictionary-sdkcore-end", c1810Zb.k);
                }
                return new Xl((JSONObject) ((Iq) this.d).c.get(), c1810Zb);
        }
    }

    public /* synthetic */ Ng(Iq iq, zzbvl zzbvlVar, Iq iq2) {
        this.b = iq;
        this.c = zzbvlVar;
        this.d = iq2;
    }
}
