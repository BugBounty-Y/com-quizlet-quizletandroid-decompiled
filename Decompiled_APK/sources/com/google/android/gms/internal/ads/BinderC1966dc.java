package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.dc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1966dc extends AbstractBinderC2814x5 {
    public final String a;
    public final int b;

    public BinderC1966dc(String str, int i) {
        super("com.google.android.gms.ads.internal.reward.client.IRewardItem");
        this.a = str;
        this.b = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            parcel2.writeNoException();
            parcel2.writeString(this.a);
            return true;
        }
        if (i != 2) {
            return false;
        }
        parcel2.writeNoException();
        parcel2.writeInt(this.b);
        return true;
    }

    public final boolean equals(Object obj) {
        if (obj != null && (obj instanceof BinderC1966dc)) {
            BinderC1966dc binderC1966dc = (BinderC1966dc) obj;
            if (com.google.android.gms.common.internal.u.l(this.a, binderC1966dc.a) && com.google.android.gms.common.internal.u.l(Integer.valueOf(this.b), Integer.valueOf(binderC1966dc.b))) {
                return true;
            }
        }
        return false;
    }
}
