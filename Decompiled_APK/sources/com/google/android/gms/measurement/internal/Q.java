package com.google.android.gms.measurement.internal;

import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.measurement.C3010j2;
import com.google.android.gms.internal.measurement.E1;
import java.util.HashMap;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final /* synthetic */ class Q implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ T b;
    public final /* synthetic */ String c;

    public /* synthetic */ Q(T t, String str, int i) {
        this.a = i;
        this.b = t;
        this.c = str;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(11, this.b, this.c);
                C3010j2 c3010j2 = new C3010j2("internal.remoteConfig", 0);
                c3010j2.b.put("getValue", new E1(uVar));
                return c3010j2;
            case 1:
                return new E1(new Q(this.b, this.c, 2));
            default:
                T t = this.b;
                C3874j c3874j = t.c.c;
                r1.L(c3874j);
                String str = this.c;
                F fP0 = c3874j.P0(str);
                HashMap map = new HashMap();
                map.put("platform", DtbConstants.NATIVE_OS_NAME);
                map.put("package_name", str);
                ((Y) t.b).g.Z();
                map.put("gmp_version", 119002L);
                if (fP0 != null) {
                    String strE = fP0.e();
                    if (strE != null) {
                        map.put("app_version", strE);
                    }
                    map.put("app_version_int", Long.valueOf(fP0.S()));
                    map.put("dynamite_version", Long.valueOf(fP0.T()));
                }
                return map;
        }
    }
}
