package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.C1614q;

/* renamed from: com.google.android.gms.internal.ads.k9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2260k9 implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2830xf b;
    public final /* synthetic */ String c;

    public /* synthetic */ C2260k9(C2830xf c2830xf, String str, int i) {
        this.a = i;
        this.b = c2830xf;
        this.c = str;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        String str = this.c;
        C2830xf c2830xf = this.b;
        switch (this.a) {
            case 0:
                String str2 = (String) obj;
                C2175i9 c2175i9 = AbstractC2346m9.a;
                return (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.aa)).booleanValue() && c2830xf != null && C2830xf.b(str)) ? c2830xf.a(str2, C1614q.f.e) : AbstractC2025es.E(str2);
            default:
                c2830xf.e.a(new RunnableC2787wf(c2830xf, (Throwable) obj, 1));
                return AbstractC2025es.E(str);
        }
    }
}
