package com.pubmatic.sdk.openwrap.eventhandler.dfp;

import androidx.annotation.NonNull;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.l;
import com.pubmatic.sdk.common.f;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public abstract class d {
    @NonNull
    public static h a(@NonNull l lVar) {
        String str = "Ad Server Error(" + lVar.a + ") - " + lVar.b;
        int i = lVar.a;
        return i != 1 ? i != 2 ? i != 3 ? new h(1006, str) : new h(1002, str) : new h(1003, str) : new h(1001, str);
    }

    public static h a(@NonNull com.google.android.gms.ads.b bVar) {
        String str = "Ad Server Error(" + bVar.a + ") - " + bVar.b;
        int i = bVar.a;
        if (i == 1) {
            return new h(h.AD_ALREADY_SHOWN, str);
        }
        if (i != 2) {
            return new h(1006, str);
        }
        return new h(h.AD_NOT_READY, str);
    }

    public static f[] a(com.google.android.gms.ads.h[] hVarArr) {
        ArrayList arrayList = new ArrayList();
        if (hVarArr != null && hVarArr.length > 0) {
            arrayList = new ArrayList();
            for (com.google.android.gms.ads.h hVar : hVarArr) {
                if (hVar != null) {
                    int i = hVar.b;
                    int i2 = hVar.a;
                    if (i2 == -3 && i == -4) {
                        POBLog.warn("DFPEventHandlerUtil", "OpenWrap SDK doesn't support Fluid ad size. It will be filtered from OpenWrap ad request.", new Object[0]);
                    } else {
                        arrayList.add(new f(i2, i));
                    }
                } else {
                    POBLog.debug("DFPEventHandlerUtil", "Filtering null size from OpenWrap ad request.", new Object[0]);
                }
            }
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        return (f[]) arrayList.toArray(new f[arrayList.size()]);
    }

    public static f a(@NonNull AdManagerAdView adManagerAdView) {
        try {
            com.google.android.gms.ads.h adSize = adManagerAdView.getAdSize();
            if (adSize != null) {
                return new f(adSize.a, adSize.b);
            }
            return null;
        } catch (Exception e) {
            POBLog.error("DFPEventHandlerUtil", "Failed to get GAM AdSize. Reason : %s", e.getMessage());
            return null;
        }
    }
}
