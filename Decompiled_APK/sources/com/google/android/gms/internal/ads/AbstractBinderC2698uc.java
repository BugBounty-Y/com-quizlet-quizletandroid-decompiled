package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.uc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC2698uc extends AbstractBinderC2814x5 implements InterfaceC2741vc {
    public AbstractBinderC2698uc() {
        super("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdLoadCallback");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            h();
        } else if (i == 2) {
            int i2 = parcel.readInt();
            AbstractC2857y5.b(parcel);
            u(i2);
        } else {
            if (i != 3) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            r(zzeVar);
        }
        parcel2.writeNoException();
        return true;
    }
}
