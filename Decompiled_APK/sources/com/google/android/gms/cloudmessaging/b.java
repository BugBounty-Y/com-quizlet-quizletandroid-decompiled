package com.google.android.gms.cloudmessaging;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;

/* loaded from: classes2.dex */
public final class b implements Parcelable.Creator {
    public final /* synthetic */ int a;

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                Intent intent = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    if (((char) i) != 1) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        intent = (Intent) AbstractC3471i3.f(parcel, i, Intent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new CloudMessage(intent);
            default:
                return new zzd(parcel.readStrongBinder());
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new CloudMessage[i];
            default:
                return new zzd[i];
        }
    }
}
