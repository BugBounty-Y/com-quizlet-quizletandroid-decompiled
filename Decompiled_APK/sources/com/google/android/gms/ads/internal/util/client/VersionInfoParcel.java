package com.google.android.gms.ads.internal.util.client;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class VersionInfoParcel extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<VersionInfoParcel> CREATOR = new android.support.v4.media.a(28);
    public final String a;
    public final int b;
    public final int c;
    public final boolean d;
    public final boolean e;

    public VersionInfoParcel(String str, int i, int i2, boolean z, boolean z2) {
        this.a = str;
        this.b = i;
        this.c = i2;
        this.d = z;
        this.e = z2;
    }

    public static VersionInfoParcel a() {
        return new VersionInfoParcel(12451000, 12451000, true, false);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.e ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public VersionInfoParcel(int i, int i2, boolean z, boolean z2) {
        String str;
        if (z) {
            str = "0";
        } else {
            str = "1";
        }
        StringBuilder sbW = android.support.v4.media.session.a.w("afma-sdk-a-v", i, ".", ".", i2);
        sbW.append(str);
        this(sbW.toString(), i, i2, z, z2);
    }
}
