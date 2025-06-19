package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;

/* loaded from: classes2.dex */
public final class f implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        int iS = AbstractC3471i3.s(parcel);
        byte[] bArrD = null;
        boolean zM = false;
        String strG = null;
        while (parcel.dataPosition() < iS) {
            int i = parcel.readInt();
            char c = (char) i;
            if (c == 1) {
                zM = AbstractC3471i3.m(i, parcel);
            } else if (c == 2) {
                bArrD = AbstractC3471i3.d(i, parcel);
            } else if (c != 3) {
                AbstractC3471i3.r(i, parcel);
            } else {
                strG = AbstractC3471i3.g(i, parcel);
            }
        }
        AbstractC3471i3.l(iS, parcel);
        return new BeginSignInRequest.PasskeysRequestOptions(strG, zM, bArrD);
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        return new BeginSignInRequest.PasskeysRequestOptions[i];
    }
}
