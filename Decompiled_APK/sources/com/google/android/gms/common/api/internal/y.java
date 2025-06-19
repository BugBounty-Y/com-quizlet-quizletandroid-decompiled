package com.google.android.gms.common.api.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.common.Feature;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.oss_licenses.zze;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class y extends AbstractC2027eu {
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ y(Object obj, int i) {
        super(2, (byte) 0);
        this.e = i;
        this.f = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2027eu
    public final void b(com.google.android.gms.common.api.c cVar, com.google.android.gms.tasks.f fVar) {
        String string;
        ArrayList arrayList;
        switch (this.e) {
            case 0:
                ((i) ((k) this.f).d).accept(cVar, fVar);
                return;
            case 1:
                com.google.android.gms.oss.licenses.d dVar = (com.google.android.gms.oss.licenses.d) cVar;
                zze zzeVar = (zze) this.f;
                synchronized (dVar) {
                    com.google.android.gms.oss.licenses.a aVarX = dVar.x();
                    if (aVarX == null) {
                        throw new RemoteException("no service for getLicenseDetail call");
                    }
                    String str = zzeVar.a;
                    Parcel parcelObtain = Parcel.obtain();
                    parcelObtain.writeInterfaceToken("com.google.android.gms.oss.licenses.IOSSLicenseService");
                    parcelObtain.writeString(str);
                    Parcel parcelV = aVarX.V(4, parcelObtain);
                    string = parcelV.readString();
                    parcelV.recycle();
                }
                fVar.b(string);
                return;
            default:
                com.google.android.gms.oss.licenses.d dVar2 = (com.google.android.gms.oss.licenses.d) cVar;
                ArrayList arrayList2 = (ArrayList) this.f;
                synchronized (dVar2) {
                    com.google.android.gms.oss.licenses.a aVarX2 = dVar2.x();
                    if (aVarX2 == null) {
                        throw new RemoteException("no service for getLicenseDetail call");
                    }
                    Parcel parcelObtain2 = Parcel.obtain();
                    parcelObtain2.writeInterfaceToken("com.google.android.gms.oss.licenses.IOSSLicenseService");
                    parcelObtain2.writeList(arrayList2);
                    Parcel parcelV2 = aVarX2.V(5, parcelObtain2);
                    arrayList = parcelV2.readArrayList(com.google.android.gms.internal.oss_licenses.a.a);
                    parcelV2.recycle();
                }
                fVar.b(arrayList);
                return;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(k kVar, Feature[] featureArr, boolean z, int i) {
        super(featureArr, z, i);
        this.e = 0;
        this.f = kVar;
    }
}
