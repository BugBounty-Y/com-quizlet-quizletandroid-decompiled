package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;

/* loaded from: classes2.dex */
public final class g implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        int iS = AbstractC3471i3.s(parcel);
        boolean zM = false;
        while (parcel.dataPosition() < iS) {
            int i = parcel.readInt();
            if (((char) i) != 1) {
                AbstractC3471i3.r(i, parcel);
            } else {
                zM = AbstractC3471i3.m(i, parcel);
            }
        }
        AbstractC3471i3.l(iS, parcel);
        return new BeginSignInRequest.PasswordRequestOptions(zM);
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        return new BeginSignInRequest.PasswordRequestOptions[i];
    }
}
