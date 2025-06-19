package com.google.android.gms.measurement.internal;

import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Pair;

/* renamed from: com.google.android.gms.measurement.internal.v0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3898v0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ D0 b;

    public /* synthetic */ RunnableC3898v0(D0 d0, int i) {
        this.a = i;
        this.b = d0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                D0 d0 = this.b;
                d0.S();
                Y y = (Y) d0.b;
                O o = y.h;
                Y.h(o);
                boolean zB = o.v.b();
                I i = y.i;
                if (zB) {
                    Y.k(i);
                    i.n.f("Deferred Deep Link already retrieved. Not fetching again.");
                    break;
                } else {
                    O o2 = y.h;
                    Y.h(o2);
                    N n = o2.w;
                    long jA = n.a();
                    n.b(1 + jA);
                    if (jA >= 5) {
                        Y.k(i);
                        i.j.f("Permanently failed to retrieve Deferred Deep Link. Reached maximum retries.");
                        o2.v.a(true);
                        break;
                    } else {
                        if (d0.u == null) {
                            d0.u = new C3902x0(d0, y, 3);
                        }
                        d0.u.c(0L);
                        break;
                    }
                }
            case 1:
                this.b.Z();
                break;
            case 2:
                P p = this.b.s;
                Y y2 = p.a;
                X x = y2.j;
                Y.k(x);
                x.S();
                if (p.c()) {
                    boolean zD = p.d();
                    D0 d02 = y2.p;
                    O o3 = y2.h;
                    if (zD) {
                        Y.h(o3);
                        o3.y.m(null);
                        Bundle bundle = new Bundle();
                        bundle.putString("source", "(not set)");
                        bundle.putString("medium", "(not set)");
                        bundle.putString("_cis", "intent");
                        bundle.putLong("_cc", 1L);
                        Y.j(d02);
                        d02.c0("auto", "_cmpx", bundle);
                    } else {
                        Y.h(o3);
                        androidx.browser.customtabs.k kVar = o3.y;
                        String strL = kVar.l();
                        if (TextUtils.isEmpty(strL)) {
                            I i2 = y2.i;
                            Y.k(i2);
                            i2.h.f("Cache still valid but referrer not found");
                        } else {
                            long jA2 = o3.z.a() / 3600000;
                            Uri uri = Uri.parse(strL);
                            Bundle bundle2 = new Bundle();
                            Pair pair = new Pair(uri.getPath(), bundle2);
                            for (String str : uri.getQueryParameterNames()) {
                                bundle2.putString(str, uri.getQueryParameter(str));
                            }
                            ((Bundle) pair.second).putLong("_cc", (jA2 - 1) * 3600000);
                            Object obj = pair.first;
                            String str2 = obj == null ? "app" : (String) obj;
                            Y.j(d02);
                            d02.c0(str2, "_cmp", (Bundle) pair.second);
                        }
                        kVar.m(null);
                    }
                    Y.h(o3);
                    o3.z.b(0L);
                    break;
                }
                break;
            default:
                this.b.Z();
                break;
        }
    }
}
