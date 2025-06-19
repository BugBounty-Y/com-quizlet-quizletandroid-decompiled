package com.google.android.gms.internal.oss_licenses;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.fido.fido2.api.common.i;

/* loaded from: classes2.dex */
public final class zze implements Comparable<zze>, Parcelable {
    public static final Parcelable.Creator<zze> CREATOR = new i(7);
    public final String a;
    public final long b;
    public final int c;
    public final String d;

    public zze(int i, long j, String str) {
        this.a = str;
        this.b = j;
        this.c = i;
        this.d = "";
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(zze zzeVar) {
        return this.a.compareTo(zzeVar.a);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof zze) {
            return this.a.equals(((zze) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.a);
        parcel.writeLong(this.b);
        parcel.writeInt(this.c);
        parcel.writeString(this.d);
    }

    public /* synthetic */ zze(Parcel parcel) {
        this.a = parcel.readString();
        this.b = parcel.readLong();
        this.c = parcel.readInt();
        this.d = parcel.readString();
    }
}
