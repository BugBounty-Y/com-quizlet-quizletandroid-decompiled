package com.google.android.gms.internal.gtm;

import android.os.BadParcelableException;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.session.a;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class zzat {
    public static final /* synthetic */ int a = 0;
    private static final ClassLoader zzb = zzat.class.getClassLoader();

    public static Parcelable zza(Parcel parcel, Parcelable.Creator creator) {
        if (parcel.readInt() == 0) {
            return null;
        }
        return (Parcelable) creator.createFromParcel(parcel);
    }

    public static HashMap zzb(Parcel parcel) {
        return parcel.readHashMap(zzb);
    }

    public static void zzc(Parcel parcel) {
        int iDataAvail = parcel.dataAvail();
        if (iDataAvail > 0) {
            throw new BadParcelableException(a.f(iDataAvail, "Parcel data not fully consumed, unread size: "));
        }
    }

    public static void zzd(Parcel parcel, Parcelable parcelable) {
        if (parcelable == null) {
            parcel.writeInt(0);
        } else {
            parcel.writeInt(1);
            parcelable.writeToParcel(parcel, 0);
        }
    }

    public static void zze(Parcel parcel, IInterface iInterface) {
        if (iInterface == null) {
            parcel.writeStrongBinder(null);
        } else {
            parcel.writeStrongBinder(iInterface.asBinder());
        }
    }

    public static boolean zzf(Parcel parcel) {
        return parcel.readInt() != 0;
    }
}
