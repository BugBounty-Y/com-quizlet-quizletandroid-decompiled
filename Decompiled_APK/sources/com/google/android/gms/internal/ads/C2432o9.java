package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.o9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2432o9 implements InterfaceC2389n9 {
    public final /* synthetic */ int a;
    public final C2493pl b;

    public C2432o9(C2493pl c2493pl, int i) {
        this.a = i;
        switch (i) {
            case 1:
                com.google.android.gms.common.internal.u.i(c2493pl, "The Inspector Manager must not be null");
                this.b = c2493pl;
                break;
            default:
                com.google.android.gms.common.internal.u.i(c2493pl, "The Inspector Manager must not be null");
                this.b = c2493pl;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) throws NumberFormatException {
        switch (this.a) {
            case 0:
                if (map == null || !map.containsKey("persistentData") || TextUtils.isEmpty((CharSequence) map.get("persistentData"))) {
                    return;
                }
                C2493pl c2493pl = this.b;
                String str = (String) map.get("persistentData");
                synchronized (c2493pl) {
                    c2493pl.x = str;
                    com.google.android.gms.ads.internal.j.C.h.d().b(c2493pl.x);
                }
                return;
            default:
                if (map == null || !map.containsKey("extras")) {
                    return;
                }
                long j = Long.MAX_VALUE;
                if (map.containsKey("expires")) {
                    try {
                        j = Long.parseLong((String) map.get("expires"));
                    } catch (NumberFormatException unused) {
                    }
                }
                C2493pl c2493pl2 = this.b;
                String str2 = (String) map.get("extras");
                synchronized (c2493pl2) {
                    c2493pl2.o = str2;
                    c2493pl2.q = j;
                    c2493pl2.i();
                }
                return;
        }
    }
}
