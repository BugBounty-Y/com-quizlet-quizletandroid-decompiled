package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.Ff, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1694Ff implements InterfaceC2389n9 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1700Gf b;

    public /* synthetic */ C1694Ff(C1700Gf c1700Gf, int i) {
        this.a = i;
        this.b = c1700Gf;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        switch (this.a) {
            case 0:
                if (map != null) {
                    String str = (String) map.get("hashCode");
                    if (!TextUtils.isEmpty(str)) {
                        C1700Gf c1700Gf = this.b;
                        if (str.equals(c1700Gf.a)) {
                            c1700Gf.c.execute(new RunnableC1989e(this, 22));
                            break;
                        }
                    }
                }
                break;
            default:
                if (map != null) {
                    String str2 = (String) map.get("hashCode");
                    if (!TextUtils.isEmpty(str2)) {
                        C1700Gf c1700Gf2 = this.b;
                        if (str2.equals(c1700Gf2.a)) {
                            c1700Gf2.c.execute(new RunnableC1989e(this, 23));
                            break;
                        }
                    }
                }
                break;
        }
    }
}
