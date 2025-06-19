package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.aa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1833aa implements InterfaceC2389n9 {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;
    public final Object d;

    public C1833aa(C2007ea c2007ea, V9 v9, androidx.appcompat.app.L l) {
        this.b = v9;
        this.c = l;
        this.d = c2007ea;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /requestReload handler: Trying to acquire lock");
                C2007ea c2007ea = (C2007ea) this.d;
                synchronized (c2007ea.c) {
                    try {
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /requestReload handler: Lock acquired");
                        com.google.android.gms.ads.internal.util.client.i.g("JS Engine is requesting an update");
                        if (c2007ea.b == 0) {
                            com.google.android.gms.ads.internal.util.client.i.g("Starting reload.");
                            c2007ea.b = 2;
                            c2007ea.o();
                        }
                        ((V9) this.b).o("/requestReload", (C1833aa) ((androidx.appcompat.app.L) this.c).b);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /requestReload handler: Lock released");
                return;
            default:
                String str = (String) map.get("asset");
                try {
                    ((N8) this.b).e3((J8) ((InterfaceC2907zC) this.d).zzb(), str);
                    return;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Failed to call onCustomClick for asset " + str + ".", e);
                    return;
                }
        }
    }

    public C1833aa(C1929cj c1929cj, Yi yi, C1843ak c1843ak, InterfaceC2907zC interfaceC2907zC) {
        this.b = (N8) c1929cj.g.get(yi.a());
        this.c = c1843ak;
        this.d = interfaceC2907zC;
    }
}
