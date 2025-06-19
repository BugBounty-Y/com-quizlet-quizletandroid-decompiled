package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;

/* loaded from: classes2.dex */
public final class zzs implements Comparator<zzr>, Parcelable {
    public static final Parcelable.Creator<zzs> CREATOR = new C2128h6(26);
    public final zzr[] a;
    public int b;
    public final String c;
    public final int d;

    public zzs(Parcel parcel) {
        this.c = parcel.readString();
        zzr[] zzrVarArr = (zzr[]) parcel.createTypedArray(zzr.CREATOR);
        String str = Yo.a;
        this.a = zzrVarArr;
        this.d = zzrVarArr.length;
    }

    public final zzs a(String str) {
        return Objects.equals(this.c, str) ? this : new zzs(str, false, this.a);
    }

    @Override // java.util.Comparator
    public final /* bridge */ /* synthetic */ int compare(zzr zzrVar, zzr zzrVar2) {
        zzr zzrVar3 = zzrVar2;
        UUID uuid = AbstractC1958dB.a;
        UUID uuid2 = zzrVar.b;
        return uuid.equals(uuid2) ? !uuid.equals(zzrVar3.b) ? 1 : 0 : uuid2.compareTo(zzrVar3.b);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // java.util.Comparator
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && zzs.class == obj.getClass()) {
            zzs zzsVar = (zzs) obj;
            if (Objects.equals(this.c, zzsVar.c) && Arrays.equals(this.a, zzsVar.a)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.b;
        if (i != 0) {
            return i;
        }
        String str = this.c;
        int iHashCode = ((str == null ? 0 : str.hashCode()) * 31) + Arrays.hashCode(this.a);
        this.b = iHashCode;
        return iHashCode;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.c);
        parcel.writeTypedArray(this.a, 0);
    }

    public zzs(String str, boolean z, zzr... zzrVarArr) {
        this.c = str;
        zzrVarArr = z ? (zzr[]) zzrVarArr.clone() : zzrVarArr;
        this.a = zzrVarArr;
        this.d = zzrVarArr.length;
        Arrays.sort(zzrVarArr, this);
    }
}
