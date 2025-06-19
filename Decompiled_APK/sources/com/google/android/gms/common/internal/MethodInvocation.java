package com.google.android.gms.common.internal;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public class MethodInvocation extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<MethodInvocation> CREATOR = new com.google.android.gms.ads.internal.f(18);
    public final int a;
    public final int b;
    public final int c;
    public final long d;
    public final long e;
    public final String f;
    public final String g;
    public final int h;
    public final int i;

    public MethodInvocation(int i, int i2, int i3, long j, long j2, String str, String str2, int i4, int i5) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = j;
        this.e = j2;
        this.f = str;
        this.g = str2;
        this.h = i4;
        this.i = i5;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 4, 8);
        parcel.writeLong(this.d);
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(this.e);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.h);
        AbstractC3489l3.m(parcel, 9, 4);
        parcel.writeInt(this.i);
        AbstractC3489l3.o(iN, parcel);
    }
}
