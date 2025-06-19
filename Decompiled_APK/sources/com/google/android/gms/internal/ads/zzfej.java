package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzfej extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfej> CREATOR = new C2128h6(20);
    public final Context a;
    public final int b;
    public final EnumC2712uq c;
    public final int d;
    public final int e;
    public final int f;
    public final String g;
    public final int h;
    public final int i;
    public final int j;

    public zzfej(int i, int i2, int i3, int i4, int i5, int i6, String str) {
        EnumC2712uq[] enumC2712uqArrValues = EnumC2712uq.values();
        this.a = null;
        this.b = i;
        this.c = enumC2712uqArrValues[i];
        this.d = i2;
        this.e = i3;
        this.f = i4;
        this.g = str;
        this.h = i5;
        this.j = new int[]{1, 2, 3}[i5];
        this.i = i6;
        int i7 = new int[]{1}[i6];
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.h(parcel, 5, this.g);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.h);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.i);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzfej(Context context, EnumC2712uq enumC2712uq, int i, int i2, int i3, String str, String str2, String str3) {
        int i4;
        EnumC2712uq.values();
        this.a = context;
        this.b = enumC2712uq.ordinal();
        this.c = enumC2712uq;
        this.d = i;
        this.e = i2;
        this.f = i3;
        this.g = str;
        if ("oldest".equals(str2)) {
            i4 = 1;
        } else {
            i4 = (!"lru".equals(str2) && "lfu".equals(str2)) ? 3 : 2;
        }
        this.j = i4;
        this.h = i4 - 1;
        "onAdClosed".equals(str3);
        this.i = 0;
    }
}
