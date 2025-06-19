package com.google.android.gms.common.internal;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class A extends p {
    public final /* synthetic */ AbstractC1655e g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(AbstractC1655e abstractC1655e, int i, Bundle bundle) {
        super(abstractC1655e, i, bundle);
        this.g = abstractC1655e;
    }

    @Override // com.google.android.gms.common.internal.p
    public final boolean a() {
        this.g.j.b(ConnectionResult.e);
        return true;
    }

    @Override // com.google.android.gms.common.internal.p
    public final void b(ConnectionResult connectionResult) {
        AbstractC1655e abstractC1655e = this.g;
        abstractC1655e.getClass();
        if ((abstractC1655e instanceof com.google.android.gms.oss.licenses.d) && abstractC1655e.v()) {
            abstractC1655e.u();
        } else {
            abstractC1655e.j.b(connectionResult);
            System.currentTimeMillis();
        }
    }
}
