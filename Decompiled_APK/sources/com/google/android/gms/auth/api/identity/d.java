package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class d implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        int iS = AbstractC3471i3.s(parcel);
        boolean zM = false;
        boolean zM2 = false;
        boolean zM3 = false;
        String strG = null;
        String strG2 = null;
        String strG3 = null;
        ArrayList arrayListI = null;
        while (parcel.dataPosition() < iS) {
            int i = parcel.readInt();
            switch ((char) i) {
                case 1:
                    zM = AbstractC3471i3.m(i, parcel);
                    break;
                case 2:
                    strG = AbstractC3471i3.g(i, parcel);
                    break;
                case 3:
                    strG2 = AbstractC3471i3.g(i, parcel);
                    break;
                case 4:
                    zM2 = AbstractC3471i3.m(i, parcel);
                    break;
                case 5:
                    strG3 = AbstractC3471i3.g(i, parcel);
                    break;
                case 6:
                    arrayListI = AbstractC3471i3.i(i, parcel);
                    break;
                case 7:
                    zM3 = AbstractC3471i3.m(i, parcel);
                    break;
                default:
                    AbstractC3471i3.r(i, parcel);
                    break;
            }
        }
        AbstractC3471i3.l(iS, parcel);
        return new BeginSignInRequest.GoogleIdTokenRequestOptions(zM, strG, strG2, zM2, strG3, arrayListI, zM3);
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        return new BeginSignInRequest.GoogleIdTokenRequestOptions[i];
    }
}
