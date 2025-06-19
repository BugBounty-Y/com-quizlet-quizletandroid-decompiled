package com.google.android.gms.common.internal;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public abstract class p {
    public Boolean a;
    public boolean b;
    public final /* synthetic */ AbstractC1655e c;
    public final int d;
    public final Bundle e;
    public final /* synthetic */ AbstractC1655e f;

    public p(AbstractC1655e abstractC1655e, int i, Bundle bundle) {
        this.f = abstractC1655e;
        Boolean bool = Boolean.TRUE;
        this.c = abstractC1655e;
        this.a = bool;
        this.b = false;
        this.d = i;
        this.e = bundle;
    }

    public abstract boolean a();

    public abstract void b(ConnectionResult connectionResult);
}
