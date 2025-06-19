package com.google.android.gms.oss.licenses;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.tasks.f;

/* loaded from: classes2.dex */
public final class b extends AbstractC2027eu {
    public final /* synthetic */ int e;
    public final /* synthetic */ String f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(String str, int i) {
        super(2, (byte) 0);
        this.e = i;
        this.f = str;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2027eu
    public final void b(com.google.android.gms.common.api.c cVar, f fVar) {
        String string;
        String string2;
        switch (this.e) {
            case 0:
                d dVar = (d) cVar;
                String str = this.f;
                synchronized (dVar) {
                    a aVarX = dVar.x();
                    if (aVarX == null) {
                        throw new RemoteException("no service for getLicenseDetail call");
                    }
                    Parcel parcelObtain = Parcel.obtain();
                    parcelObtain.writeInterfaceToken("com.google.android.gms.oss.licenses.IOSSLicenseService");
                    parcelObtain.writeString(str);
                    Parcel parcelV = aVarX.V(3, parcelObtain);
                    string = parcelV.readString();
                    parcelV.recycle();
                }
                fVar.b(string);
                return;
            default:
                d dVar2 = (d) cVar;
                String str2 = this.f;
                synchronized (dVar2) {
                    a aVarX2 = dVar2.x();
                    if (aVarX2 == null) {
                        throw new RemoteException("no service for getLicenseDetail call");
                    }
                    Parcel parcelObtain2 = Parcel.obtain();
                    parcelObtain2.writeInterfaceToken("com.google.android.gms.oss.licenses.IOSSLicenseService");
                    parcelObtain2.writeString(str2);
                    Parcel parcelV2 = aVarX2.V(2, parcelObtain2);
                    string2 = parcelV2.readString();
                    parcelV2.recycle();
                }
                fVar.b(string2);
                return;
        }
    }
}
