package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.qc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC2527qc extends AbstractBinderC2814x5 implements InterfaceC2569rc {
    public AbstractBinderC2527qc() {
        super("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdCallback");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC2312lc c2269kc;
        switch (i) {
            case 1:
                i();
                break;
            case 2:
                h();
                break;
            case 3:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    c2269kc = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardItem");
                    c2269kc = iInterfaceQueryLocalInterface instanceof InterfaceC2312lc ? (InterfaceC2312lc) iInterfaceQueryLocalInterface : new C2269kc(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                q0(c2269kc);
                break;
            case 4:
                int i2 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                k0(i2);
                break;
            case 5:
                zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
                AbstractC2857y5.b(parcel);
                h3(zzeVar);
                break;
            case 6:
                f();
                break;
            case 7:
                zze();
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }
}
