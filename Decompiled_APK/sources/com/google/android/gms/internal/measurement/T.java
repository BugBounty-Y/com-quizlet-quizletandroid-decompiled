package com.google.android.gms.internal.measurement;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;

/* loaded from: classes2.dex */
public final class T implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ T(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                String strG = null;
                String strG2 = null;
                String strG3 = null;
                Bundle bundleC = null;
                String strG4 = null;
                boolean zM = false;
                long jP = 0;
                long jP2 = 0;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    switch ((char) i) {
                        case 1:
                            jP = AbstractC3471i3.p(i, parcel);
                            break;
                        case 2:
                            jP2 = AbstractC3471i3.p(i, parcel);
                            break;
                        case 3:
                            zM = AbstractC3471i3.m(i, parcel);
                            break;
                        case 4:
                            strG = AbstractC3471i3.g(i, parcel);
                            break;
                        case 5:
                            strG2 = AbstractC3471i3.g(i, parcel);
                            break;
                        case 6:
                            strG3 = AbstractC3471i3.g(i, parcel);
                            break;
                        case 7:
                            bundleC = AbstractC3471i3.c(i, parcel);
                            break;
                        case '\b':
                            strG4 = AbstractC3471i3.g(i, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new zzdh(jP, jP2, zM, strG, strG2, strG3, bundleC, strG4);
            default:
                int iS2 = AbstractC3471i3.s(parcel);
                String strG5 = null;
                int iO = 0;
                Intent intent = null;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    char c = (char) i2;
                    if (c == 1) {
                        iO = AbstractC3471i3.o(i2, parcel);
                    } else if (c == 2) {
                        strG5 = AbstractC3471i3.g(i2, parcel);
                    } else if (c != 3) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        intent = (Intent) AbstractC3471i3.f(parcel, i2, Intent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new zzdj(iO, strG5, intent);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzdh[i];
            default:
                return new zzdj[i];
        }
    }
}
