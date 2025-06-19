package com.google.android.gms.internal.ads;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzbvl extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbvl> CREATOR = new C2128h6(14);
    public final Bundle a;
    public final VersionInfoParcel b;
    public final ApplicationInfo c;
    public final String d;
    public final ArrayList e;
    public final PackageInfo f;
    public final String g;
    public final String h;
    public zzfej i;
    public String j;
    public final boolean k;
    public final boolean l;
    public final Bundle m;
    public final Bundle n;
    public final int o;

    public zzbvl(Bundle bundle, VersionInfoParcel versionInfoParcel, ApplicationInfo applicationInfo, String str, ArrayList arrayList, PackageInfo packageInfo, String str2, String str3, zzfej zzfejVar, String str4, boolean z, boolean z2, Bundle bundle2, Bundle bundle3, int i) {
        this.a = bundle;
        this.b = versionInfoParcel;
        this.d = str;
        this.c = applicationInfo;
        this.e = arrayList;
        this.f = packageInfo;
        this.g = str2;
        this.h = str3;
        this.i = zzfejVar;
        this.j = str4;
        this.k = z;
        this.l = z2;
        this.m = bundle2;
        this.n = bundle3;
        this.o = i;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.c(parcel, 1, this.a);
        AbstractC3489l3.g(parcel, 2, this.b, i);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.j(parcel, 5, this.e);
        AbstractC3489l3.g(parcel, 6, this.f, i);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.h(parcel, 9, this.h);
        AbstractC3489l3.g(parcel, 10, this.i, i);
        AbstractC3489l3.h(parcel, 11, this.j);
        AbstractC3489l3.m(parcel, 12, 4);
        parcel.writeInt(this.k ? 1 : 0);
        AbstractC3489l3.m(parcel, 13, 4);
        parcel.writeInt(this.l ? 1 : 0);
        AbstractC3489l3.c(parcel, 14, this.m);
        AbstractC3489l3.c(parcel, 15, this.n);
        AbstractC3489l3.m(parcel, 16, 4);
        parcel.writeInt(this.o);
        AbstractC3489l3.o(iN, parcel);
    }
}
