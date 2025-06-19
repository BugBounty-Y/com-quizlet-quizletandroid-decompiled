package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.qg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2531qg implements InterfaceC2237jn {
    public final List a;

    public C2531qg(List list) {
        this.a = list;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2237jn
    public final void p() {
        for (com.google.common.util.concurrent.e eVar : this.a) {
            L9 l9 = new L9(28);
            eVar.a(new Qv(0, eVar, l9), Kv.a);
        }
    }

    public C2531qg(AbstractC2359mg abstractC2359mg) {
        this.a = Collections.singletonList(AbstractC2025es.E(abstractC2359mg));
    }
}
