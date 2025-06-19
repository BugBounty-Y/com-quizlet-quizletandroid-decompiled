package com.google.android.gms.internal.fido;

import android.os.IBinder;
import android.os.IInterface;

/* loaded from: classes2.dex */
public final class l0 implements IInterface {
    public final IBinder a;
    public final String b;

    public l0(IBinder iBinder, String str) {
        this.a = iBinder;
        this.b = str;
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        return this.a;
    }
}
