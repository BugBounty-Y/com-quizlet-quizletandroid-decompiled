package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class zzah extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzah> CREATOR = new C3091a(7);
    public int a;
    public boolean b;

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzah)) {
            return false;
        }
        zzah zzahVar = (zzah) obj;
        return this.a == zzahVar.a && com.google.android.gms.common.internal.u.l(Boolean.valueOf(this.b), Boolean.valueOf(zzahVar.b));
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(this.a), Boolean.valueOf(this.b)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        int i2 = this.a;
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(i2);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }
}
