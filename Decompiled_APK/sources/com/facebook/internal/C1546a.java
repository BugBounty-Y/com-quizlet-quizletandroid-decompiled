package com.facebook.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.internal.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1546a implements IInterface {
    public final IBinder a;

    public C1546a(IBinder binder) {
        Intrinsics.checkNotNullParameter(binder, "binder");
        this.a = binder;
    }

    public final String V() {
        Parcel parcelObtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain, "obtain()");
        Parcel parcelObtain2 = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain2, "obtain()");
        try {
            parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
            this.a.transact(1, parcelObtain, parcelObtain2, 0);
            parcelObtain2.readException();
            return parcelObtain2.readString();
        } finally {
            parcelObtain2.recycle();
            parcelObtain.recycle();
        }
    }

    public final boolean X() {
        Parcel parcelObtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain, "obtain()");
        Parcel parcelObtain2 = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain2, "obtain()");
        try {
            parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
            parcelObtain.writeInt(1);
            this.a.transact(2, parcelObtain, parcelObtain2, 0);
            parcelObtain2.readException();
            return parcelObtain2.readInt() != 0;
        } finally {
            parcelObtain2.recycle();
            parcelObtain.recycle();
        }
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        return this.a;
    }
}
