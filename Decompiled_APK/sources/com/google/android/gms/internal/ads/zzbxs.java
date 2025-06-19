package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzbxs extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbxs> CREATOR = new C2128h6(18);
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;
    public final List e;
    public final boolean f;
    public final boolean g;
    public final List h;

    public zzbxs(String str, String str2, boolean z, boolean z2, List list, boolean z3, boolean z4, List list2) {
        this.a = str;
        this.b = str2;
        this.c = z;
        this.d = z2;
        this.e = list;
        this.f = z3;
        this.g = z4;
        this.h = list2 == null ? new ArrayList() : list2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c ? 1 : 0);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.j(parcel, 6, this.e);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.f ? 1 : 0);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.j(parcel, 9, this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
