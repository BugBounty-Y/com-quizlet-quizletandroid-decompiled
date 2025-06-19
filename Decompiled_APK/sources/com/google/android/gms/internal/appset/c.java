package com.google.android.gms.internal.appset;

import android.os.IBinder;
import android.os.IInterface;

/* loaded from: classes2.dex */
public final class c implements IInterface {
    public final IBinder a;

    public c(IBinder iBinder) {
        this.a = iBinder;
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        return this.a;
    }
}
