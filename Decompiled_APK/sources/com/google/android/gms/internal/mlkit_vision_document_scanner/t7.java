package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.BitmapTeleporter;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class t7 implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ t7(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                BitmapTeleporter bitmapTeleporter = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    if (((char) i) != 1) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        bitmapTeleporter = (BitmapTeleporter) AbstractC3471i3.f(parcel, i, BitmapTeleporter.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new zzry(bitmapTeleporter);
            default:
                int iS2 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK = null;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    if (((char) i2) != 1) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        arrayListK = AbstractC3471i3.k(parcel, i2, zzry.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new zzsa(arrayListK);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzry[i];
            default:
                return new zzsa[i];
        }
    }
}
