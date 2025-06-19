package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzfpf extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfpf> CREATOR = new C2128h6(23);
    public final int a;
    public C2384n4 b = null;
    public byte[] c;

    public zzfpf(int i, byte[] bArr) {
        this.a = i;
        this.c = bArr;
        a();
    }

    public final void a() {
        C2384n4 c2384n4 = this.b;
        if (c2384n4 != null || this.c == null) {
            if (c2384n4 == null || this.c != null) {
                if (c2384n4 != null && this.c != null) {
                    throw new IllegalStateException("Invalid internal representation - full");
                }
                if (c2384n4 != null || this.c != null) {
                    throw new IllegalStateException("Impossible");
                }
                throw new IllegalStateException("Invalid internal representation - empty");
            }
        }
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        byte[] bArrD = this.c;
        if (bArrD == null) {
            bArrD = this.b.d();
        }
        AbstractC3489l3.d(parcel, 2, bArrD);
        AbstractC3489l3.o(iN, parcel);
    }
}
