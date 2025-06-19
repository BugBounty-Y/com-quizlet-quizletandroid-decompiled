package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1624z extends AbstractBinderC2814x5 implements A {
    public AbstractBinderC1624z() {
        super("com.google.android.gms.ads.internal.client.IAdLoadCallback");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            q();
        } else {
            if (i != 2) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            t2(zzeVar);
        }
        parcel2.writeNoException();
        return true;
    }
}
