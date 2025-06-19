package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class zzai extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzai> CREATOR = new com.google.android.gms.common.i(10);
    public final T a;
    public final T b;
    public final T c;
    public final int d;

    public zzai(T t, T t2, T t3, int i) {
        this.a = t;
        this.b = t2;
        this.c = t3;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof zzai)) {
            return false;
        }
        zzai zzaiVar = (zzai) obj;
        return u.l(this.a, zzaiVar.a) && u.l(this.b, zzaiVar.b) && u.l(this.c, zzaiVar.c) && this.d == zzaiVar.d;
    }

    public final int hashCode() {
        Integer numValueOf = Integer.valueOf(this.d);
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, numValueOf});
    }

    public final String toString() {
        T t = this.a;
        String strG = com.google.android.gms.common.util.c.g(t == null ? null : t.m());
        T t2 = this.b;
        String strG2 = com.google.android.gms.common.util.c.g(t2 == null ? null : t2.m());
        T t3 = this.c;
        String strG3 = com.google.android.gms.common.util.c.g(t3 != null ? t3.m() : null);
        StringBuilder sbH = AbstractC0147y.h("HmacSecretExtension{coseKeyAgreement=", strG, ", saltEnc=", strG2, ", saltAuth=");
        sbH.append(strG3);
        sbH.append(", getPinUvAuthProtocol=");
        return android.support.v4.media.session.a.r(sbH, this.d, "}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        T t = this.a;
        AbstractC3489l3.d(parcel, 1, t == null ? null : t.m());
        T t2 = this.b;
        AbstractC3489l3.d(parcel, 2, t2 == null ? null : t2.m());
        T t3 = this.c;
        AbstractC3489l3.d(parcel, 3, t3 != null ? t3.m() : null);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
