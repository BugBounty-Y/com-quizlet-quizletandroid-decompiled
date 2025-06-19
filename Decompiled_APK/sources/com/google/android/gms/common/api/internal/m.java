package com.google.android.gms.common.api.internal;

import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class m implements InterfaceC1644b {
    public final /* synthetic */ C1647e a;

    public m(C1647e c1647e) {
        this.a = c1647e;
    }

    @Override // com.google.android.gms.common.api.internal.InterfaceC1644b
    public final void a(boolean z) {
        Boolean boolValueOf = Boolean.valueOf(z);
        Ls ls = this.a.n;
        ls.sendMessage(ls.obtainMessage(1, boolValueOf));
    }
}
