package com.google.firebase.perf.metrics.validator;

import com.google.firebase.perf.v1.C3977g;

/* loaded from: classes2.dex */
public final class a extends e {
    public static final com.google.firebase.perf.logging.a b = com.google.firebase.perf.logging.a.d();
    public final C3977g a;

    public a(C3977g c3977g) {
        this.a = c3977g;
    }

    @Override // com.google.firebase.perf.metrics.validator.e
    public final boolean a() {
        com.google.firebase.perf.logging.a aVar = b;
        C3977g c3977g = this.a;
        if (c3977g == null) {
            aVar.f("ApplicationInfo is null");
        } else if (!c3977g.G()) {
            aVar.f("GoogleAppId is null");
        } else if (!c3977g.E()) {
            aVar.f("AppInstanceId is null");
        } else if (!c3977g.F()) {
            aVar.f("ApplicationProcessState is null");
        } else {
            if (!c3977g.D()) {
                return true;
            }
            if (!c3977g.B().A()) {
                aVar.f("AndroidAppInfo.packageName is null");
            } else {
                if (c3977g.B().B()) {
                    return true;
                }
                aVar.f("AndroidAppInfo.sdkVersion is null");
            }
        }
        aVar.f("ApplicationInfo is invalid");
        return false;
    }
}
