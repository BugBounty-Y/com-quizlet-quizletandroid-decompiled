package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class zzq extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzq> CREATOR = new i(3);
    public final long a;
    public final T b;
    public final T c;
    public final T d;

    public zzq(long j, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        u.h(bArr);
        T tK = T.k(bArr.length, bArr);
        u.h(bArr2);
        T tK2 = T.k(bArr2.length, bArr2);
        u.h(bArr3);
        T tK3 = T.k(bArr3.length, bArr3);
        this.a = j;
        this.b = tK;
        this.c = tK2;
        this.d = tK3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof zzq)) {
            return false;
        }
        zzq zzqVar = (zzq) obj;
        return this.a == zzqVar.a && u.l(this.b, zzqVar.b) && u.l(this.c, zzqVar.c) && u.l(this.d, zzqVar.d);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Long.valueOf(this.a), this.b, this.c, this.d});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 8);
        parcel.writeLong(this.a);
        AbstractC3489l3.d(parcel, 2, this.b.m());
        AbstractC3489l3.d(parcel, 3, this.c.m());
        AbstractC3489l3.d(parcel, 4, this.d.m());
        AbstractC3489l3.o(iN, parcel);
    }
}
