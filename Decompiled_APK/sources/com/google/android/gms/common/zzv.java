package com.google.android.gms.common;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.internal.G;
import com.google.android.gms.common.internal.H;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzv extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzv> CREATOR = new i(4);
    public final String a;
    public final l b;
    public final boolean c;
    public final boolean d;

    public zzv(String str, l lVar, boolean z, boolean z2) {
        this.a = str;
        this.b = lVar;
        this.c = z;
        this.d = z2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        l lVar = this.b;
        if (lVar == null) {
            Log.w("GoogleCertificatesQuery", "certificate binder is null");
            lVar = null;
        }
        AbstractC3489l3.e(parcel, 2, lVar);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c ? 1 : 0);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzv(String str, IBinder iBinder, boolean z, boolean z2) {
        H g;
        this.a = str;
        l lVar = null;
        if (iBinder != null) {
            try {
                int i = k.c;
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.common.internal.ICertData");
                if (iInterfaceQueryLocalInterface instanceof H) {
                    g = (H) iInterfaceQueryLocalInterface;
                } else {
                    g = new G(iBinder, "com.google.android.gms.common.internal.ICertData", 3);
                }
                com.google.android.gms.dynamic.a aVarJ = g.j();
                byte[] bArr = aVarJ == null ? null : (byte[]) com.google.android.gms.dynamic.b.I3(aVarJ);
                if (bArr != null) {
                    lVar = new l(bArr);
                } else {
                    Log.e("GoogleCertificatesQuery", "Could not unwrap certificate");
                }
            } catch (RemoteException e) {
                Log.e("GoogleCertificatesQuery", "Could not unwrap certificate", e);
            }
        }
        this.b = lVar;
        this.c = z;
        this.d = z2;
    }
}
