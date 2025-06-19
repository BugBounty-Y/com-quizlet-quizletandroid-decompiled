package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class zzfp extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfp> CREATOR = new C1589d0(4);
    public final String a;
    public final int b;
    public final zzm c;
    public final int d;

    public zzfp(String str, int i, zzm zzmVar, int i2) {
        this.a = str;
        this.b = i;
        this.c = zzmVar;
        this.d = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzfp)) {
            return false;
        }
        zzfp zzfpVar = (zzfp) obj;
        return this.a.equals(zzfpVar.a) && this.b == zzfpVar.b && this.c.a(zzfpVar.c);
    }

    public final int hashCode() {
        return Objects.hash(this.a, Integer.valueOf(this.b), this.c);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
