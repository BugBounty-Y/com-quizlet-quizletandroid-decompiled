package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.a6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1822a6 extends AbstractBinderC2814x5 implements InterfaceC1866b6 {
    public AbstractBinderC1822a6() {
        super("com.google.android.gms.ads.internal.appopen.client.IAppOpenAdLoadCallback");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        Y5 x5;
        if (i == 1) {
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder == null) {
                x5 = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.appopen.client.IAppOpenAd");
                x5 = iInterfaceQueryLocalInterface instanceof Y5 ? (Y5) iInterfaceQueryLocalInterface : new X5(strongBinder, "com.google.android.gms.ads.internal.appopen.client.IAppOpenAd", 0);
            }
            AbstractC2857y5.b(parcel);
            a4(x5);
        } else if (i == 2) {
            parcel.readInt();
            AbstractC2857y5.b(parcel);
        } else {
            if (i != 3) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            a0(zzeVar);
        }
        parcel2.writeNoException();
        return true;
    }
}
