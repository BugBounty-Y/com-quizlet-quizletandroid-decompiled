package com.google.android.gms.ads.internal.client;

import android.location.Location;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.ads.internal.client.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1589d0 implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ C1589d0(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                String strG = null;
                String strG2 = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    char c = (char) i;
                    if (c == 1) {
                        strG = AbstractC3471i3.g(i, parcel);
                    } else if (c != 2) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        strG2 = AbstractC3471i3.g(i, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new zzc(strG, strG2);
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                int iO = 0;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    if (((char) i2) != 2) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        iO = AbstractC3471i3.o(i2, parcel);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new zzee(iO);
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG3 = null;
                int iO2 = 0;
                int iO3 = 0;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    char c2 = (char) i3;
                    if (c2 == 1) {
                        iO2 = AbstractC3471i3.o(i3, parcel);
                    } else if (c2 == 2) {
                        iO3 = AbstractC3471i3.o(i3, parcel);
                    } else if (c2 != 3) {
                        AbstractC3471i3.r(i3, parcel);
                    } else {
                        strG3 = AbstractC3471i3.g(i3, parcel);
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new zzex(iO2, iO3, strG3);
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                String strG4 = null;
                String strG5 = null;
                zze zzeVar = null;
                IBinder iBinderN = null;
                int iO4 = 0;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    char c3 = (char) i4;
                    if (c3 == 1) {
                        iO4 = AbstractC3471i3.o(i4, parcel);
                    } else if (c3 == 2) {
                        strG4 = AbstractC3471i3.g(i4, parcel);
                    } else if (c3 == 3) {
                        strG5 = AbstractC3471i3.g(i4, parcel);
                    } else if (c3 == 4) {
                        zzeVar = (zze) AbstractC3471i3.f(parcel, i4, zze.CREATOR);
                    } else if (c3 != 5) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        iBinderN = AbstractC3471i3.n(i4, parcel);
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new zze(iO4, strG4, strG5, zzeVar, iBinderN);
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                int iO5 = 0;
                String strG6 = null;
                zzm zzmVar = null;
                int iO6 = 0;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    char c4 = (char) i5;
                    if (c4 == 1) {
                        strG6 = AbstractC3471i3.g(i5, parcel);
                    } else if (c4 == 2) {
                        iO5 = AbstractC3471i3.o(i5, parcel);
                    } else if (c4 == 3) {
                        zzmVar = (zzm) AbstractC3471i3.f(parcel, i5, zzm.CREATOR);
                    } else if (c4 != 4) {
                        AbstractC3471i3.r(i5, parcel);
                    } else {
                        iO6 = AbstractC3471i3.o(i5, parcel);
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new zzfp(strG6, iO5, zzmVar, iO6);
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                int iO7 = 0;
                int iO8 = 0;
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    char c5 = (char) i6;
                    if (c5 == 1) {
                        iO7 = AbstractC3471i3.o(i6, parcel);
                    } else if (c5 != 2) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        iO8 = AbstractC3471i3.o(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new zzfr(iO7, iO8);
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                String strG7 = null;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    if (((char) i7) != 15) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        strG7 = AbstractC3471i3.g(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new zzft(strG7);
            case 7:
                int iS8 = AbstractC3471i3.s(parcel);
                boolean zM = false;
                boolean zM2 = false;
                boolean zM3 = false;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    char c6 = (char) i8;
                    if (c6 == 2) {
                        zM = AbstractC3471i3.m(i8, parcel);
                    } else if (c6 == 3) {
                        zM2 = AbstractC3471i3.m(i8, parcel);
                    } else if (c6 != 4) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        zM3 = AbstractC3471i3.m(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                return new zzfw(zM, zM2, zM3);
            case 8:
                int iS9 = AbstractC3471i3.s(parcel);
                long jP = 0;
                long jP2 = 0;
                int iO9 = 0;
                int iO10 = 0;
                boolean zM4 = false;
                int iO11 = 0;
                boolean zM5 = false;
                boolean zM6 = false;
                int iO12 = 0;
                int iO13 = 0;
                int iO14 = 0;
                Bundle bundleC = null;
                ArrayList arrayListI = null;
                String strG8 = null;
                zzft zzftVar = null;
                Location location = null;
                String strG9 = null;
                Bundle bundleC2 = null;
                Bundle bundleC3 = null;
                ArrayList arrayListI2 = null;
                String strG10 = null;
                String strG11 = null;
                zzc zzcVar = null;
                String strG12 = null;
                ArrayList arrayListI3 = null;
                String strG13 = null;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    switch ((char) i9) {
                        case 1:
                            iO9 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case 2:
                            jP = AbstractC3471i3.p(i9, parcel);
                            break;
                        case 3:
                            bundleC = AbstractC3471i3.c(i9, parcel);
                            break;
                        case 4:
                            iO10 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case 5:
                            arrayListI = AbstractC3471i3.i(i9, parcel);
                            break;
                        case 6:
                            zM4 = AbstractC3471i3.m(i9, parcel);
                            break;
                        case 7:
                            iO11 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case '\b':
                            zM5 = AbstractC3471i3.m(i9, parcel);
                            break;
                        case '\t':
                            strG8 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case '\n':
                            zzftVar = (zzft) AbstractC3471i3.f(parcel, i9, zzft.CREATOR);
                            break;
                        case 11:
                            location = (Location) AbstractC3471i3.f(parcel, i9, Location.CREATOR);
                            break;
                        case '\f':
                            strG9 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case '\r':
                            bundleC2 = AbstractC3471i3.c(i9, parcel);
                            break;
                        case 14:
                            bundleC3 = AbstractC3471i3.c(i9, parcel);
                            break;
                        case 15:
                            arrayListI2 = AbstractC3471i3.i(i9, parcel);
                            break;
                        case 16:
                            strG10 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case 17:
                            strG11 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case 18:
                            zM6 = AbstractC3471i3.m(i9, parcel);
                            break;
                        case 19:
                            zzcVar = (zzc) AbstractC3471i3.f(parcel, i9, zzc.CREATOR);
                            break;
                        case 20:
                            iO12 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case 21:
                            strG12 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case EventType.WINDOW_STATE /* 22 */:
                            arrayListI3 = AbstractC3471i3.i(i9, parcel);
                            break;
                        case EventType.AUDIO /* 23 */:
                            iO13 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case EventType.VIDEO /* 24 */:
                            strG13 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case EventType.SUBS /* 25 */:
                            iO14 = AbstractC3471i3.o(i9, parcel);
                            break;
                        case EventType.CDN /* 26 */:
                            jP2 = AbstractC3471i3.p(i9, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i9, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new zzm(iO9, jP, bundleC, iO10, arrayListI, zM4, iO11, zM5, strG8, zzftVar, location, strG9, bundleC2, bundleC3, arrayListI2, strG10, strG11, zM6, zzcVar, iO12, strG12, arrayListI3, iO13, strG13, iO14, jP2);
            case 9:
                int iS10 = AbstractC3471i3.s(parcel);
                int iO15 = 0;
                int iO16 = 0;
                boolean zM7 = false;
                int iO17 = 0;
                int iO18 = 0;
                boolean zM8 = false;
                boolean zM9 = false;
                boolean zM10 = false;
                boolean zM11 = false;
                boolean zM12 = false;
                boolean zM13 = false;
                boolean zM14 = false;
                boolean zM15 = false;
                String strG14 = null;
                zzr[] zzrVarArr = null;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    switch ((char) i10) {
                        case 2:
                            strG14 = AbstractC3471i3.g(i10, parcel);
                            break;
                        case 3:
                            iO15 = AbstractC3471i3.o(i10, parcel);
                            break;
                        case 4:
                            iO16 = AbstractC3471i3.o(i10, parcel);
                            break;
                        case 5:
                            zM7 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case 6:
                            iO17 = AbstractC3471i3.o(i10, parcel);
                            break;
                        case 7:
                            iO18 = AbstractC3471i3.o(i10, parcel);
                            break;
                        case '\b':
                            zzrVarArr = (zzr[]) AbstractC3471i3.j(parcel, i10, zzr.CREATOR);
                            break;
                        case '\t':
                            zM8 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case '\n':
                            zM9 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case 11:
                            zM10 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case '\f':
                            zM11 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case '\r':
                            zM12 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case 14:
                            zM13 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case 15:
                            zM14 = AbstractC3471i3.m(i10, parcel);
                            break;
                        case 16:
                            zM15 = AbstractC3471i3.m(i10, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i10, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                return new zzr(strG14, iO15, iO16, zM7, iO17, iO18, zzrVarArr, zM8, zM9, zM10, zM11, zM12, zM13, zM14, zM15);
            case 10:
                int iS11 = AbstractC3471i3.s(parcel);
                long jP3 = 0;
                String strG15 = null;
                int iO19 = 0;
                int iO20 = 0;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    char c7 = (char) i11;
                    if (c7 == 1) {
                        iO19 = AbstractC3471i3.o(i11, parcel);
                    } else if (c7 == 2) {
                        iO20 = AbstractC3471i3.o(i11, parcel);
                    } else if (c7 == 3) {
                        strG15 = AbstractC3471i3.g(i11, parcel);
                    } else if (c7 != 4) {
                        AbstractC3471i3.r(i11, parcel);
                    } else {
                        jP3 = AbstractC3471i3.p(i11, parcel);
                    }
                }
                AbstractC3471i3.l(iS11, parcel);
                return new zzt(jP3, iO19, iO20, strG15);
            case 11:
                int iS12 = AbstractC3471i3.s(parcel);
                String strG16 = null;
                zze zzeVar2 = null;
                Bundle bundleC4 = null;
                String strG17 = null;
                String strG18 = null;
                String strG19 = null;
                String strG20 = null;
                long jP4 = 0;
                while (parcel.dataPosition() < iS12) {
                    int i12 = parcel.readInt();
                    switch ((char) i12) {
                        case 1:
                            strG16 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 2:
                            jP4 = AbstractC3471i3.p(i12, parcel);
                            break;
                        case 3:
                            zzeVar2 = (zze) AbstractC3471i3.f(parcel, i12, zze.CREATOR);
                            break;
                        case 4:
                            bundleC4 = AbstractC3471i3.c(i12, parcel);
                            break;
                        case 5:
                            strG17 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 6:
                            strG18 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 7:
                            strG19 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case '\b':
                            strG20 = AbstractC3471i3.g(i12, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i12, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS12, parcel);
                return new zzv(strG16, jP4, zzeVar2, bundleC4, strG17, strG18, strG19, strG20);
            default:
                int iS13 = AbstractC3471i3.s(parcel);
                int iO21 = 0;
                while (parcel.dataPosition() < iS13) {
                    int i13 = parcel.readInt();
                    if (((char) i13) != 2) {
                        AbstractC3471i3.r(i13, parcel);
                    } else {
                        iO21 = AbstractC3471i3.o(i13, parcel);
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                return new zzx(iO21);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzc[i];
            case 1:
                return new zzee[i];
            case 2:
                return new zzex[i];
            case 3:
                return new zze[i];
            case 4:
                return new zzfp[i];
            case 5:
                return new zzfr[i];
            case 6:
                return new zzft[i];
            case 7:
                return new zzfw[i];
            case 8:
                return new zzm[i];
            case 9:
                return new zzr[i];
            case 10:
                return new zzt[i];
            case 11:
                return new zzv[i];
            default:
                return new zzx[i];
        }
    }
}
