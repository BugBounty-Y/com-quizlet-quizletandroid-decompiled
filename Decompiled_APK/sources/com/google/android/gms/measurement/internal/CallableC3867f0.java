package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import java.util.concurrent.Callable;

/* renamed from: com.google.android.gms.measurement.internal.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class CallableC3867f0 implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzr b;
    public final /* synthetic */ Bundle c;
    public final /* synthetic */ BinderC3869g0 d;

    public /* synthetic */ CallableC3867f0(BinderC3869g0 binderC3869g0, zzr zzrVar, Bundle bundle, int i) {
        this.a = i;
        this.b = zzrVar;
        this.c = bundle;
        this.d = binderC3869g0;
    }

    @Override // java.util.concurrent.Callable
    public final /* bridge */ /* synthetic */ Object call() {
        switch (this.a) {
            case 0:
                BinderC3869g0 binderC3869g0 = this.d;
                binderC3869g0.a.j();
                zzr zzrVar = this.b;
                return binderC3869g0.a.h(this.c, zzrVar);
            default:
                BinderC3869g0 binderC3869g02 = this.d;
                binderC3869g02.a.j();
                zzr zzrVar2 = this.b;
                return binderC3869g02.a.h(this.c, zzrVar2);
        }
    }
}
