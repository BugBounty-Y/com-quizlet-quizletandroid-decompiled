package com.google.android.gms.ads.internal.overlay;

import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzc extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzc> CREATOR = new android.support.v4.media.a(26);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final Intent h;
    public final a i;
    public final boolean j;

    public zzc(String str, String str2, String str3, String str4, String str5, String str6, String str7, Intent intent, IBinder iBinder, boolean z) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
        this.f = str6;
        this.g = str7;
        this.h = intent;
        this.i = (a) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder));
        this.j = z;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.h(parcel, 5, this.d);
        AbstractC3489l3.h(parcel, 6, this.e);
        AbstractC3489l3.h(parcel, 7, this.f);
        AbstractC3489l3.h(parcel, 8, this.g);
        AbstractC3489l3.g(parcel, 9, this.h, i);
        AbstractC3489l3.e(parcel, 10, new com.google.android.gms.dynamic.b(this.i));
        AbstractC3489l3.m(parcel, 11, 4);
        parcel.writeInt(this.j ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzc(Intent intent, a aVar) {
        this(null, null, null, null, null, null, null, intent, new com.google.android.gms.dynamic.b(aVar), false);
    }

    public zzc(String str, String str2, String str3, String str4, String str5, String str6, String str7, a aVar) {
        this(str, str2, str3, str4, str5, str6, str7, null, new com.google.android.gms.dynamic.b(aVar), false);
    }
}
