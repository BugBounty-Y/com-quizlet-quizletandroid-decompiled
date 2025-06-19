package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zzx;

/* renamed from: com.google.android.gms.internal.ads.lo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2324lo implements Uo {
    public final /* synthetic */ int a;
    public final Object b;
    public final boolean c;

    public /* synthetic */ C2324lo(boolean z, int i, Object obj) {
        this.a = i;
        this.b = obj;
        this.c = z;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        switch (this.a) {
            case 1:
                ((Og) obj).b.putString("gct", (String) this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                String str = (String) this.b;
                if (str != null) {
                    Bundle bundleD = AbstractC2096gb.d(og.a, "pii");
                    bundleD.putString("afai", str);
                    bundleD.putBoolean("is_afai_lat", this.c);
                    break;
                }
                break;
            case 1:
                Bundle bundle = ((Og) obj).a;
                bundle.putString("gct", (String) this.b);
                if (this.c) {
                    bundle.putString("de", "1");
                    break;
                }
                break;
            default:
                Bundle bundle2 = ((Og) obj).a;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u5)).booleanValue()) {
                    bundle2.putBoolean("app_switched", this.c);
                }
                zzx zzxVar = (zzx) this.b;
                if (zzxVar != null) {
                    int i = zzxVar.a;
                    if (i != 1) {
                        if (i == 2) {
                            bundle2.putString("avo", "l");
                            break;
                        }
                    } else {
                        bundle2.putString("avo", "p");
                        break;
                    }
                }
                break;
        }
    }
}
