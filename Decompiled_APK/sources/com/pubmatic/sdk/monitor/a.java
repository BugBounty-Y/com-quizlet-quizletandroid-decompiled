package com.pubmatic.sdk.monitor;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public abstract class a extends Binder implements b {

    /* renamed from: com.pubmatic.sdk.monitor.a$a, reason: collision with other inner class name */
    public static class C0015a implements b {
        public static b a;
        private IBinder b;

        public C0015a(IBinder iBinder) {
            this.b = iBinder;
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this.b;
        }

        @Override // com.pubmatic.sdk.monitor.b
        public String getMonitorData() throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.pubmatic.sdk.monitor.IPOBMonitorService");
                if (!this.b.transact(1, parcelObtain, parcelObtain2, 0) && a.getDefaultImpl() != null) {
                    return a.getDefaultImpl().getMonitorData();
                }
                parcelObtain2.readException();
                return parcelObtain2.readString();
            } finally {
                parcelObtain2.recycle();
                parcelObtain.recycle();
            }
        }
    }

    public a() {
        attachInterface(this, "com.pubmatic.sdk.monitor.IPOBMonitorService");
    }

    public static b asInterface(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.pubmatic.sdk.monitor.IPOBMonitorService");
        return (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof b)) ? new C0015a(iBinder) : (b) iInterfaceQueryLocalInterface;
    }

    public static b getDefaultImpl() {
        return C0015a.a;
    }

    public static boolean setDefaultImpl(b bVar) {
        if (C0015a.a != null) {
            throw new IllegalStateException("setDefaultImpl() called twice");
        }
        if (bVar == null) {
            return false;
        }
        C0015a.a = bVar;
        return true;
    }

    @Override // android.os.IInterface
    public IBinder asBinder() {
        return this;
    }

    @Override // com.pubmatic.sdk.monitor.b
    public abstract /* synthetic */ String getMonitorData() throws RemoteException;

    @Override // android.os.Binder
    public boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i != 1) {
            if (i != 1598968902) {
                return super.onTransact(i, parcel, parcel2, i2);
            }
            parcel2.writeString("com.pubmatic.sdk.monitor.IPOBMonitorService");
            return true;
        }
        parcel.enforceInterface("com.pubmatic.sdk.monitor.IPOBMonitorService");
        String monitorData = getMonitorData();
        parcel2.writeNoException();
        parcel2.writeString(monitorData);
        return true;
    }
}
