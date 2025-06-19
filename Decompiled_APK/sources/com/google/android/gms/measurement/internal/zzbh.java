package com.google.android.gms.measurement.internal;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;

/* loaded from: classes2.dex */
public final class zzbh extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbh> CREATOR = new com.google.android.gms.fido.fido2.api.common.i(12);
    public final String a;
    public final zzbf b;
    public final String c;
    public final long d;

    public zzbh(zzbh zzbhVar, long j) {
        com.google.android.gms.common.internal.u.h(zzbhVar);
        this.a = zzbhVar.a;
        this.b = zzbhVar.b;
        this.c = zzbhVar.c;
        this.d = j;
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.b);
        StringBuilder sb = new StringBuilder("origin=");
        sb.append(this.c);
        sb.append(",name=");
        return AbstractC0147y.g(sb, this.a, ",params=", strValueOf);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        com.google.android.gms.fido.fido2.api.common.i.a(this, parcel, i);
    }

    public zzbh(String str, zzbf zzbfVar, String str2, long j) {
        this.a = str;
        this.b = zzbfVar;
        this.c = str2;
        this.d = j;
    }
}
