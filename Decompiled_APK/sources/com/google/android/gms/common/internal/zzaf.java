package com.google.android.gms.common.internal;

import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class zzaf extends Exception {
    public final ConnectionResult a;

    public zzaf(ConnectionResult connectionResult) {
        u.a("ResolvableConnectionException can only be created with a connection result containing a resolution.", (connectionResult.b == 0 || connectionResult.c == null) ? false : true);
        this.a = connectionResult;
    }
}
