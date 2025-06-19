package com.google.android.gms.internal.ads;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zzee;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.h6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2128h6 implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ C2128h6(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                boolean zM = false;
                boolean zM2 = false;
                boolean zM3 = false;
                long jP = 0;
                ParcelFileDescriptor parcelFileDescriptor = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    char c = (char) i;
                    if (c == 2) {
                        parcelFileDescriptor = (ParcelFileDescriptor) AbstractC3471i3.f(parcel, i, ParcelFileDescriptor.CREATOR);
                    } else if (c == 3) {
                        zM = AbstractC3471i3.m(i, parcel);
                    } else if (c == 4) {
                        zM2 = AbstractC3471i3.m(i, parcel);
                    } else if (c == 5) {
                        jP = AbstractC3471i3.p(i, parcel);
                    } else if (c != 6) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        zM3 = AbstractC3471i3.m(i, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new zzbbc(parcelFileDescriptor, zM, zM2, jP, zM3);
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                boolean zM4 = false;
                int iO = 0;
                String strG = null;
                String strG2 = null;
                String strG3 = null;
                String strG4 = null;
                Bundle bundleC = null;
                String strG5 = null;
                long jP2 = 0;
                long jP3 = 0;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    switch ((char) i2) {
                        case 2:
                            strG = AbstractC3471i3.g(i2, parcel);
                            break;
                        case 3:
                            jP2 = AbstractC3471i3.p(i2, parcel);
                            break;
                        case 4:
                            strG2 = AbstractC3471i3.g(i2, parcel);
                            break;
                        case 5:
                            strG3 = AbstractC3471i3.g(i2, parcel);
                            break;
                        case 6:
                            strG4 = AbstractC3471i3.g(i2, parcel);
                            break;
                        case 7:
                            bundleC = AbstractC3471i3.c(i2, parcel);
                            break;
                        case '\b':
                            zM4 = AbstractC3471i3.m(i2, parcel);
                            break;
                        case '\t':
                            jP3 = AbstractC3471i3.p(i2, parcel);
                            break;
                        case '\n':
                            strG5 = AbstractC3471i3.g(i2, parcel);
                            break;
                        case 11:
                            iO = AbstractC3471i3.o(i2, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i2, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new zzbbf(strG, jP2, strG2, strG3, strG4, bundleC, zM4, jP3, strG5, iO);
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                int iO2 = 0;
                boolean zM5 = false;
                int iO3 = 0;
                boolean zM6 = false;
                int iO4 = 0;
                boolean zM7 = false;
                int iO5 = 0;
                int iO6 = 0;
                boolean zM8 = false;
                int iO7 = 0;
                zzfw zzfwVar = null;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    switch ((char) i3) {
                        case 1:
                            iO2 = AbstractC3471i3.o(i3, parcel);
                            break;
                        case 2:
                            zM5 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 3:
                            iO3 = AbstractC3471i3.o(i3, parcel);
                            break;
                        case 4:
                            zM6 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 5:
                            iO4 = AbstractC3471i3.o(i3, parcel);
                            break;
                        case 6:
                            zzfwVar = (zzfw) AbstractC3471i3.f(parcel, i3, zzfw.CREATOR);
                            break;
                        case 7:
                            zM7 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case '\b':
                            iO5 = AbstractC3471i3.o(i3, parcel);
                            break;
                        case '\t':
                            iO6 = AbstractC3471i3.o(i3, parcel);
                            break;
                        case '\n':
                            zM8 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 11:
                            iO7 = AbstractC3471i3.o(i3, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i3, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new zzbfv(iO2, zM5, iO3, zM6, iO4, zzfwVar, zM7, iO5, iO6, zM8, iO7);
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                String strG6 = null;
                String[] strArrH = null;
                String[] strArrH2 = null;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    char c2 = (char) i4;
                    if (c2 == 1) {
                        strG6 = AbstractC3471i3.g(i4, parcel);
                    } else if (c2 == 2) {
                        strArrH = AbstractC3471i3.h(i4, parcel);
                    } else if (c2 != 3) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        strArrH2 = AbstractC3471i3.h(i4, parcel);
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new zzblh(strG6, strArrH, strArrH2);
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                long jP4 = 0;
                boolean zM9 = false;
                int iO8 = 0;
                boolean zM10 = false;
                String strG7 = null;
                byte[] bArrD = null;
                String[] strArrH3 = null;
                String[] strArrH4 = null;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    switch ((char) i5) {
                        case 1:
                            zM9 = AbstractC3471i3.m(i5, parcel);
                            break;
                        case 2:
                            strG7 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 3:
                            iO8 = AbstractC3471i3.o(i5, parcel);
                            break;
                        case 4:
                            bArrD = AbstractC3471i3.d(i5, parcel);
                            break;
                        case 5:
                            strArrH3 = AbstractC3471i3.h(i5, parcel);
                            break;
                        case 6:
                            strArrH4 = AbstractC3471i3.h(i5, parcel);
                            break;
                        case 7:
                            zM10 = AbstractC3471i3.m(i5, parcel);
                            break;
                        case '\b':
                            jP4 = AbstractC3471i3.p(i5, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i5, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new zzblj(zM9, strG7, iO8, bArrD, strArrH3, strArrH4, zM10, jP4);
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                String strG8 = null;
                boolean zM11 = false;
                int iO9 = 0;
                String strG9 = null;
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    char c3 = (char) i6;
                    if (c3 == 1) {
                        strG8 = AbstractC3471i3.g(i6, parcel);
                    } else if (c3 == 2) {
                        zM11 = AbstractC3471i3.m(i6, parcel);
                    } else if (c3 == 3) {
                        iO9 = AbstractC3471i3.o(i6, parcel);
                    } else if (c3 != 4) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        strG9 = AbstractC3471i3.g(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new zzblu(strG8, iO9, strG9, zM11);
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                String strG10 = null;
                Bundle bundleC2 = null;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    char c4 = (char) i7;
                    if (c4 == 1) {
                        strG10 = AbstractC3471i3.g(i7, parcel);
                    } else if (c4 != 2) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        bundleC2 = AbstractC3471i3.c(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new zzbme(bundleC2, strG10);
            case 7:
                int iS8 = AbstractC3471i3.s(parcel);
                int iO10 = 0;
                int iO11 = 0;
                String strG11 = null;
                int iO12 = 0;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    char c5 = (char) i8;
                    if (c5 == 1) {
                        iO12 = AbstractC3471i3.o(i8, parcel);
                    } else if (c5 == 2) {
                        strG11 = AbstractC3471i3.g(i8, parcel);
                    } else if (c5 == 3) {
                        iO11 = AbstractC3471i3.o(i8, parcel);
                    } else if (c5 != 1000) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        iO10 = AbstractC3471i3.o(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                return new zzbmg(iO10, iO12, strG11, iO11);
            case 8:
                int iS9 = AbstractC3471i3.s(parcel);
                int iO13 = 0;
                int iO14 = 0;
                int iO15 = 0;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    char c6 = (char) i9;
                    if (c6 == 1) {
                        iO13 = AbstractC3471i3.o(i9, parcel);
                    } else if (c6 == 2) {
                        iO14 = AbstractC3471i3.o(i9, parcel);
                    } else if (c6 != 3) {
                        AbstractC3471i3.r(i9, parcel);
                    } else {
                        iO15 = AbstractC3471i3.o(i9, parcel);
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new zzbrz(iO13, iO14, iO15);
            case 9:
                int iS10 = AbstractC3471i3.s(parcel);
                IBinder iBinderN = null;
                IBinder iBinderN2 = null;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    char c7 = (char) i10;
                    if (c7 == 1) {
                        iBinderN = AbstractC3471i3.n(i10, parcel);
                    } else if (c7 != 2) {
                        AbstractC3471i3.r(i10, parcel);
                    } else {
                        iBinderN2 = AbstractC3471i3.n(i10, parcel);
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                return new zzbud(iBinderN, iBinderN2);
            case 10:
                int iS11 = AbstractC3471i3.s(parcel);
                Bundle bundleC3 = null;
                zzm zzmVar = null;
                com.google.android.gms.ads.internal.client.zzr zzrVar = null;
                String strG12 = null;
                ApplicationInfo applicationInfo = null;
                PackageInfo packageInfo = null;
                String strG13 = null;
                String strG14 = null;
                String strG15 = null;
                VersionInfoParcel versionInfoParcel = null;
                Bundle bundleC4 = null;
                ArrayList arrayListI = null;
                Bundle bundleC5 = null;
                String strG16 = null;
                String strG17 = null;
                ArrayList arrayListI2 = null;
                String strG18 = null;
                zzbfv zzbfvVar = null;
                ArrayList arrayListI3 = null;
                String strG19 = null;
                String strG20 = null;
                String strG21 = null;
                Bundle bundleC6 = null;
                String strG22 = null;
                zzee zzeeVar = null;
                Bundle bundleC7 = null;
                String strG23 = null;
                String strG24 = null;
                String strG25 = null;
                ArrayList arrayListE = null;
                String strG26 = null;
                ArrayList arrayListI4 = null;
                ArrayList arrayListI5 = null;
                String strG27 = null;
                zzbmg zzbmgVar = null;
                String strG28 = null;
                Bundle bundleC8 = null;
                int iO16 = 0;
                int iO17 = 0;
                boolean zM12 = false;
                int iO18 = 0;
                int iO19 = 0;
                boolean zM13 = false;
                int iO20 = 0;
                int iO21 = 0;
                boolean zM14 = false;
                boolean zM15 = false;
                int iO22 = 0;
                boolean zM16 = false;
                boolean zM17 = false;
                int iO23 = 0;
                boolean zM18 = false;
                boolean zM19 = false;
                boolean zM20 = false;
                float f = 0.0f;
                float f2 = 0.0f;
                long jP5 = 0;
                long jP6 = 0;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    switch ((char) i11) {
                        case 1:
                            iO16 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 2:
                            bundleC3 = AbstractC3471i3.c(i11, parcel);
                            break;
                        case 3:
                            zzmVar = (zzm) AbstractC3471i3.f(parcel, i11, zzm.CREATOR);
                            break;
                        case 4:
                            zzrVar = (com.google.android.gms.ads.internal.client.zzr) AbstractC3471i3.f(parcel, i11, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                            break;
                        case 5:
                            strG12 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 6:
                            applicationInfo = (ApplicationInfo) AbstractC3471i3.f(parcel, i11, ApplicationInfo.CREATOR);
                            break;
                        case 7:
                            packageInfo = (PackageInfo) AbstractC3471i3.f(parcel, i11, PackageInfo.CREATOR);
                            break;
                        case '\b':
                            strG13 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '\t':
                            strG14 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '\n':
                            strG15 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 11:
                            versionInfoParcel = (VersionInfoParcel) AbstractC3471i3.f(parcel, i11, VersionInfoParcel.CREATOR);
                            break;
                        case '\f':
                            bundleC4 = AbstractC3471i3.c(i11, parcel);
                            break;
                        case '\r':
                            iO17 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 14:
                            arrayListI = AbstractC3471i3.i(i11, parcel);
                            break;
                        case 15:
                            bundleC5 = AbstractC3471i3.c(i11, parcel);
                            break;
                        case 16:
                            zM12 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case 17:
                        case EventType.WINDOW_STATE /* 22 */:
                        case EventType.AUDIO /* 23 */:
                        case EventType.VIDEO /* 24 */:
                        case ' ':
                        case '&':
                        case '>':
                        default:
                            AbstractC3471i3.r(i11, parcel);
                            break;
                        case 18:
                            iO18 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 19:
                            iO19 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 20:
                            AbstractC3471i3.t(parcel, i11, 4);
                            f = parcel.readFloat();
                            break;
                        case 21:
                            strG16 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case EventType.SUBS /* 25 */:
                            jP5 = AbstractC3471i3.p(i11, parcel);
                            break;
                        case EventType.CDN /* 26 */:
                            strG17 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 27:
                            arrayListI2 = AbstractC3471i3.i(i11, parcel);
                            break;
                        case 28:
                            strG18 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 29:
                            zzbfvVar = (zzbfv) AbstractC3471i3.f(parcel, i11, zzbfv.CREATOR);
                            break;
                        case 30:
                            arrayListI3 = AbstractC3471i3.i(i11, parcel);
                            break;
                        case 31:
                            jP6 = AbstractC3471i3.p(i11, parcel);
                            break;
                        case '!':
                            strG19 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '\"':
                            AbstractC3471i3.t(parcel, i11, 4);
                            f2 = parcel.readFloat();
                            break;
                        case '#':
                            iO20 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case '$':
                            iO21 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case '%':
                            zM14 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case '\'':
                            strG20 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case RequestError.NETWORK_FAILURE /* 40 */:
                            zM13 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case RequestError.NO_DEV_KEY /* 41 */:
                            strG21 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '*':
                            zM15 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case '+':
                            iO22 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case ',':
                            bundleC6 = AbstractC3471i3.c(i11, parcel);
                            break;
                        case '-':
                            strG22 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '.':
                            zzeeVar = (zzee) AbstractC3471i3.f(parcel, i11, zzee.CREATOR);
                            break;
                        case '/':
                            zM16 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case '0':
                            bundleC7 = AbstractC3471i3.c(i11, parcel);
                            break;
                        case '1':
                            strG23 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                            strG24 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '3':
                            strG25 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '4':
                            zM17 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case '5':
                            arrayListE = AbstractC3471i3.e(i11, parcel);
                            break;
                        case '6':
                            strG26 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '7':
                            arrayListI4 = AbstractC3471i3.i(i11, parcel);
                            break;
                        case '8':
                            iO23 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case '9':
                            zM18 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case ':':
                            zM19 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case ';':
                            zM20 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case '<':
                            arrayListI5 = AbstractC3471i3.i(i11, parcel);
                            break;
                        case '=':
                            strG27 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case '?':
                            zzbmgVar = (zzbmg) AbstractC3471i3.f(parcel, i11, zzbmg.CREATOR);
                            break;
                        case '@':
                            strG28 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 'A':
                            bundleC8 = AbstractC3471i3.c(i11, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS11, parcel);
                return new zzbur(iO16, bundleC3, zzmVar, zzrVar, strG12, applicationInfo, packageInfo, strG13, strG14, strG15, versionInfoParcel, bundleC4, iO17, arrayListI, bundleC5, zM12, iO18, iO19, f, strG16, jP5, strG17, arrayListI2, strG18, zzbfvVar, arrayListI3, jP6, strG19, f2, zM13, iO20, iO21, zM14, strG20, strG21, zM15, iO22, bundleC6, strG22, zzeeVar, zM16, bundleC7, strG23, strG24, strG25, zM17, arrayListE, strG26, arrayListI4, iO23, zM18, zM19, zM20, arrayListI5, strG27, zzbmgVar, strG28, bundleC8);
            case 11:
                int iS12 = AbstractC3471i3.s(parcel);
                ArrayList arrayListI6 = null;
                boolean zM21 = false;
                while (parcel.dataPosition() < iS12) {
                    int i12 = parcel.readInt();
                    char c8 = (char) i12;
                    if (c8 == 2) {
                        zM21 = AbstractC3471i3.m(i12, parcel);
                    } else if (c8 != 3) {
                        AbstractC3471i3.r(i12, parcel);
                    } else {
                        arrayListI6 = AbstractC3471i3.i(i12, parcel);
                    }
                }
                AbstractC3471i3.l(iS12, parcel);
                return new zzbut(zM21, arrayListI6);
            case 12:
                int iS13 = AbstractC3471i3.s(parcel);
                String strG29 = null;
                while (parcel.dataPosition() < iS13) {
                    int i13 = parcel.readInt();
                    if (((char) i13) != 1) {
                        AbstractC3471i3.r(i13, parcel);
                    } else {
                        strG29 = AbstractC3471i3.g(i13, parcel);
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                return new zzbuv(strG29);
            case 13:
                int iS14 = AbstractC3471i3.s(parcel);
                ParcelFileDescriptor parcelFileDescriptor2 = null;
                while (parcel.dataPosition() < iS14) {
                    int i14 = parcel.readInt();
                    if (((char) i14) != 2) {
                        AbstractC3471i3.r(i14, parcel);
                    } else {
                        parcelFileDescriptor2 = (ParcelFileDescriptor) AbstractC3471i3.f(parcel, i14, ParcelFileDescriptor.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS14, parcel);
                return new zzbvj(parcelFileDescriptor2);
            case 14:
                int iS15 = AbstractC3471i3.s(parcel);
                boolean zM22 = false;
                boolean zM23 = false;
                int iO24 = 0;
                Bundle bundleC9 = null;
                VersionInfoParcel versionInfoParcel2 = null;
                ApplicationInfo applicationInfo2 = null;
                String strG30 = null;
                ArrayList arrayListI7 = null;
                PackageInfo packageInfo2 = null;
                String strG31 = null;
                String strG32 = null;
                zzfej zzfejVar = null;
                String strG33 = null;
                Bundle bundleC10 = null;
                Bundle bundleC11 = null;
                while (parcel.dataPosition() < iS15) {
                    int i15 = parcel.readInt();
                    switch ((char) i15) {
                        case 1:
                            bundleC9 = AbstractC3471i3.c(i15, parcel);
                            break;
                        case 2:
                            versionInfoParcel2 = (VersionInfoParcel) AbstractC3471i3.f(parcel, i15, VersionInfoParcel.CREATOR);
                            break;
                        case 3:
                            applicationInfo2 = (ApplicationInfo) AbstractC3471i3.f(parcel, i15, ApplicationInfo.CREATOR);
                            break;
                        case 4:
                            strG30 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case 5:
                            arrayListI7 = AbstractC3471i3.i(i15, parcel);
                            break;
                        case 6:
                            packageInfo2 = (PackageInfo) AbstractC3471i3.f(parcel, i15, PackageInfo.CREATOR);
                            break;
                        case 7:
                            strG31 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case '\b':
                        default:
                            AbstractC3471i3.r(i15, parcel);
                            break;
                        case '\t':
                            strG32 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case '\n':
                            zzfejVar = (zzfej) AbstractC3471i3.f(parcel, i15, zzfej.CREATOR);
                            break;
                        case 11:
                            strG33 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case '\f':
                            zM22 = AbstractC3471i3.m(i15, parcel);
                            break;
                        case '\r':
                            zM23 = AbstractC3471i3.m(i15, parcel);
                            break;
                        case 14:
                            bundleC10 = AbstractC3471i3.c(i15, parcel);
                            break;
                        case 15:
                            bundleC11 = AbstractC3471i3.c(i15, parcel);
                            break;
                        case 16:
                            iO24 = AbstractC3471i3.o(i15, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS15, parcel);
                return new zzbvl(bundleC9, versionInfoParcel2, applicationInfo2, strG30, arrayListI7, packageInfo2, strG31, strG32, zzfejVar, strG33, zM22, zM23, bundleC10, bundleC11, iO24);
            case 15:
                int iS16 = AbstractC3471i3.s(parcel);
                zzm zzmVar2 = null;
                String strG34 = null;
                while (parcel.dataPosition() < iS16) {
                    int i16 = parcel.readInt();
                    char c9 = (char) i16;
                    if (c9 == 2) {
                        zzmVar2 = (zzm) AbstractC3471i3.f(parcel, i16, zzm.CREATOR);
                    } else if (c9 != 3) {
                        AbstractC3471i3.r(i16, parcel);
                    } else {
                        strG34 = AbstractC3471i3.g(i16, parcel);
                    }
                }
                AbstractC3471i3.l(iS16, parcel);
                return new zzbwe(zzmVar2, strG34);
            case 16:
                int iS17 = AbstractC3471i3.s(parcel);
                int iO25 = 0;
                String strG35 = null;
                while (parcel.dataPosition() < iS17) {
                    int i17 = parcel.readInt();
                    char c10 = (char) i17;
                    if (c10 == 2) {
                        strG35 = AbstractC3471i3.g(i17, parcel);
                    } else if (c10 != 3) {
                        AbstractC3471i3.r(i17, parcel);
                    } else {
                        iO25 = AbstractC3471i3.o(i17, parcel);
                    }
                }
                AbstractC3471i3.l(iS17, parcel);
                return new zzbwj(strG35, iO25);
            case 17:
                int iS18 = AbstractC3471i3.s(parcel);
                String strG36 = null;
                String strG37 = null;
                while (parcel.dataPosition() < iS18) {
                    int i18 = parcel.readInt();
                    char c11 = (char) i18;
                    if (c11 == 1) {
                        strG36 = AbstractC3471i3.g(i18, parcel);
                    } else if (c11 != 2) {
                        AbstractC3471i3.r(i18, parcel);
                    } else {
                        strG37 = AbstractC3471i3.g(i18, parcel);
                    }
                }
                AbstractC3471i3.l(iS18, parcel);
                return new zzbxe(strG36, strG37);
            case 18:
                int iS19 = AbstractC3471i3.s(parcel);
                String strG38 = null;
                String strG39 = null;
                ArrayList arrayListI8 = null;
                ArrayList arrayListI9 = null;
                boolean zM24 = false;
                boolean zM25 = false;
                boolean zM26 = false;
                boolean zM27 = false;
                while (parcel.dataPosition() < iS19) {
                    int i19 = parcel.readInt();
                    switch ((char) i19) {
                        case 2:
                            strG38 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 3:
                            strG39 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 4:
                            zM24 = AbstractC3471i3.m(i19, parcel);
                            break;
                        case 5:
                            zM25 = AbstractC3471i3.m(i19, parcel);
                            break;
                        case 6:
                            arrayListI8 = AbstractC3471i3.i(i19, parcel);
                            break;
                        case 7:
                            zM26 = AbstractC3471i3.m(i19, parcel);
                            break;
                        case '\b':
                            zM27 = AbstractC3471i3.m(i19, parcel);
                            break;
                        case '\t':
                            arrayListI9 = AbstractC3471i3.i(i19, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i19, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS19, parcel);
                return new zzbxs(strG38, strG39, zM24, zM25, arrayListI8, zM26, zM27, arrayListI9);
            case 19:
                int iS20 = AbstractC3471i3.s(parcel);
                String strG40 = null;
                String strG41 = null;
                com.google.android.gms.ads.internal.client.zzr zzrVar2 = null;
                zzm zzmVar3 = null;
                String strG42 = null;
                int iO26 = 0;
                while (parcel.dataPosition() < iS20) {
                    int i20 = parcel.readInt();
                    switch ((char) i20) {
                        case 1:
                            strG40 = AbstractC3471i3.g(i20, parcel);
                            break;
                        case 2:
                            strG41 = AbstractC3471i3.g(i20, parcel);
                            break;
                        case 3:
                            zzrVar2 = (com.google.android.gms.ads.internal.client.zzr) AbstractC3471i3.f(parcel, i20, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                            break;
                        case 4:
                            zzmVar3 = (zzm) AbstractC3471i3.f(parcel, i20, zzm.CREATOR);
                            break;
                        case 5:
                            iO26 = AbstractC3471i3.o(i20, parcel);
                            break;
                        case 6:
                            strG42 = AbstractC3471i3.g(i20, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i20, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS20, parcel);
                return new zzbyz(strG40, strG41, zzrVar2, zzmVar3, iO26, strG42);
            case 20:
                int iS21 = AbstractC3471i3.s(parcel);
                int iO27 = 0;
                int iO28 = 0;
                int iO29 = 0;
                int iO30 = 0;
                int iO31 = 0;
                int iO32 = 0;
                String strG43 = null;
                while (parcel.dataPosition() < iS21) {
                    int i21 = parcel.readInt();
                    switch ((char) i21) {
                        case 1:
                            iO27 = AbstractC3471i3.o(i21, parcel);
                            break;
                        case 2:
                            iO28 = AbstractC3471i3.o(i21, parcel);
                            break;
                        case 3:
                            iO29 = AbstractC3471i3.o(i21, parcel);
                            break;
                        case 4:
                            iO30 = AbstractC3471i3.o(i21, parcel);
                            break;
                        case 5:
                            strG43 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 6:
                            iO31 = AbstractC3471i3.o(i21, parcel);
                            break;
                        case 7:
                            iO32 = AbstractC3471i3.o(i21, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i21, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS21, parcel);
                return new zzfej(iO27, iO28, iO29, iO30, iO31, iO32, strG43);
            case 21:
                int iS22 = AbstractC3471i3.s(parcel);
                byte[] bArrD2 = null;
                int iO33 = 0;
                while (parcel.dataPosition() < iS22) {
                    int i22 = parcel.readInt();
                    char c12 = (char) i22;
                    if (c12 == 1) {
                        iO33 = AbstractC3471i3.o(i22, parcel);
                    } else if (c12 != 2) {
                        AbstractC3471i3.r(i22, parcel);
                    } else {
                        bArrD2 = AbstractC3471i3.d(i22, parcel);
                    }
                }
                AbstractC3471i3.l(iS22, parcel);
                return new zzfpa(iO33, bArrD2);
            case EventType.WINDOW_STATE /* 22 */:
                int iS23 = AbstractC3471i3.s(parcel);
                String strG44 = null;
                int iO34 = 0;
                String strG45 = null;
                while (parcel.dataPosition() < iS23) {
                    int i23 = parcel.readInt();
                    char c13 = (char) i23;
                    if (c13 == 1) {
                        iO34 = AbstractC3471i3.o(i23, parcel);
                    } else if (c13 == 2) {
                        strG44 = AbstractC3471i3.g(i23, parcel);
                    } else if (c13 != 3) {
                        AbstractC3471i3.r(i23, parcel);
                    } else {
                        strG45 = AbstractC3471i3.g(i23, parcel);
                    }
                }
                AbstractC3471i3.l(iS23, parcel);
                return new zzfpd(iO34, strG44, strG45);
            case EventType.AUDIO /* 23 */:
                int iS24 = AbstractC3471i3.s(parcel);
                byte[] bArrD3 = null;
                int iO35 = 0;
                while (parcel.dataPosition() < iS24) {
                    int i24 = parcel.readInt();
                    char c14 = (char) i24;
                    if (c14 == 1) {
                        iO35 = AbstractC3471i3.o(i24, parcel);
                    } else if (c14 != 2) {
                        AbstractC3471i3.r(i24, parcel);
                    } else {
                        bArrD3 = AbstractC3471i3.d(i24, parcel);
                    }
                }
                AbstractC3471i3.l(iS24, parcel);
                return new zzfpf(iO35, bArrD3);
            case EventType.VIDEO /* 24 */:
                int iS25 = AbstractC3471i3.s(parcel);
                String strG46 = null;
                String strG47 = null;
                int iO36 = 0;
                int iO37 = 0;
                int iO38 = 0;
                while (parcel.dataPosition() < iS25) {
                    int i25 = parcel.readInt();
                    char c15 = (char) i25;
                    if (c15 == 1) {
                        iO36 = AbstractC3471i3.o(i25, parcel);
                    } else if (c15 == 2) {
                        iO37 = AbstractC3471i3.o(i25, parcel);
                    } else if (c15 == 3) {
                        strG46 = AbstractC3471i3.g(i25, parcel);
                    } else if (c15 == 4) {
                        strG47 = AbstractC3471i3.g(i25, parcel);
                    } else if (c15 != 5) {
                        AbstractC3471i3.r(i25, parcel);
                    } else {
                        iO38 = AbstractC3471i3.o(i25, parcel);
                    }
                }
                AbstractC3471i3.l(iS25, parcel);
                return new zzfpm(strG46, strG47, iO36, iO37, iO38);
            case EventType.SUBS /* 25 */:
                int iS26 = AbstractC3471i3.s(parcel);
                int iO39 = 0;
                byte[] bArrD4 = null;
                int iO40 = 0;
                while (parcel.dataPosition() < iS26) {
                    int i26 = parcel.readInt();
                    char c16 = (char) i26;
                    if (c16 == 1) {
                        iO39 = AbstractC3471i3.o(i26, parcel);
                    } else if (c16 == 2) {
                        bArrD4 = AbstractC3471i3.d(i26, parcel);
                    } else if (c16 != 3) {
                        AbstractC3471i3.r(i26, parcel);
                    } else {
                        iO40 = AbstractC3471i3.o(i26, parcel);
                    }
                }
                AbstractC3471i3.l(iS26, parcel);
                return new zzfpo(iO39, bArrD4, iO40);
            case EventType.CDN /* 26 */:
                return new zzs(parcel);
            default:
                return new zzr(parcel);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzbbc[i];
            case 1:
                return new zzbbf[i];
            case 2:
                return new zzbfv[i];
            case 3:
                return new zzblh[i];
            case 4:
                return new zzblj[i];
            case 5:
                return new zzblu[i];
            case 6:
                return new zzbme[i];
            case 7:
                return new zzbmg[i];
            case 8:
                return new zzbrz[i];
            case 9:
                return new zzbud[i];
            case 10:
                return new zzbur[i];
            case 11:
                return new zzbut[i];
            case 12:
                return new zzbuv[i];
            case 13:
                return new zzbvj[i];
            case 14:
                return new zzbvl[i];
            case 15:
                return new zzbwe[i];
            case 16:
                return new zzbwj[i];
            case 17:
                return new zzbxe[i];
            case 18:
                return new zzbxs[i];
            case 19:
                return new zzbyz[i];
            case 20:
                return new zzfej[i];
            case 21:
                return new zzfpa[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new zzfpd[i];
            case EventType.AUDIO /* 23 */:
                return new zzfpf[i];
            case EventType.VIDEO /* 24 */:
                return new zzfpm[i];
            case EventType.SUBS /* 25 */:
                return new zzfpo[i];
            case EventType.CDN /* 26 */:
                return new zzs[i];
            default:
                return new zzr[i];
        }
    }
}
