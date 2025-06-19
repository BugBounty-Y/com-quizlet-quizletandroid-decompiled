package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class zzf extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzf> CREATOR = new com.google.android.gms.common.i(27);
    public final T a;
    public final T b;

    public zzf(T t, T t2) {
        this.a = t;
        this.b = t2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof zzf)) {
            return false;
        }
        zzf zzfVar = (zzf) obj;
        return u.l(this.a, zzfVar.a) && u.l(this.b, zzfVar.b);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        T t = this.a;
        AbstractC3489l3.d(parcel, 1, t == null ? null : t.m());
        T t2 = this.b;
        AbstractC3489l3.d(parcel, 2, t2 != null ? t2.m() : null);
        AbstractC3489l3.o(iN, parcel);
    }
}
