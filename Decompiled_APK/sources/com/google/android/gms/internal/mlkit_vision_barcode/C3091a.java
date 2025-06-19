package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Point;
import android.os.Parcel;
import android.os.Parcelable;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3091a implements Parcelable.Creator {
    public final /* synthetic */ int a;

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                String strG = null;
                String strG2 = null;
                int iO = 0;
                String strG3 = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    char c = (char) i;
                    if (c == 2) {
                        iO = AbstractC3471i3.o(i, parcel);
                    } else if (c == 3) {
                        strG = AbstractC3471i3.g(i, parcel);
                    } else if (c == 4) {
                        strG3 = AbstractC3471i3.g(i, parcel);
                    } else if (c != 5) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        strG2 = AbstractC3471i3.g(i, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                zzn zznVar = new zzn();
                zznVar.a = iO;
                zznVar.b = strG;
                zznVar.c = strG3;
                zznVar.d = strG2;
                return zznVar;
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                double d = 0.0d;
                double d2 = 0.0d;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    char c2 = (char) i2;
                    if (c2 == 2) {
                        AbstractC3471i3.t(parcel, i2, 8);
                        d = parcel.readDouble();
                    } else if (c2 != 3) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        AbstractC3471i3.t(parcel, i2, 8);
                        d2 = parcel.readDouble();
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                zzo zzoVar = new zzo();
                zzoVar.a = d;
                zzoVar.b = d2;
                return zzoVar;
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG4 = null;
                String strG5 = null;
                String strG6 = null;
                String strG7 = null;
                String strG8 = null;
                String strG9 = null;
                String strG10 = null;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    switch ((char) i3) {
                        case 2:
                            strG4 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 3:
                            strG5 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 4:
                            strG6 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 5:
                            strG7 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 6:
                            strG8 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 7:
                            strG9 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case '\b':
                            strG10 = AbstractC3471i3.g(i3, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i3, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                zzp zzpVar = new zzp();
                zzpVar.a = strG4;
                zzpVar.b = strG5;
                zzpVar.c = strG6;
                zzpVar.d = strG7;
                zzpVar.e = strG8;
                zzpVar.f = strG9;
                zzpVar.g = strG10;
                return zzpVar;
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                String strG11 = null;
                int iO2 = 0;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    char c3 = (char) i4;
                    if (c3 == 2) {
                        iO2 = AbstractC3471i3.o(i4, parcel);
                    } else if (c3 != 3) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        strG11 = AbstractC3471i3.g(i4, parcel);
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                zzq zzqVar = new zzq();
                zzqVar.a = iO2;
                zzqVar.b = strG11;
                return zzqVar;
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                String strG12 = null;
                String strG13 = null;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    char c4 = (char) i5;
                    if (c4 == 2) {
                        strG12 = AbstractC3471i3.g(i5, parcel);
                    } else if (c4 != 3) {
                        AbstractC3471i3.r(i5, parcel);
                    } else {
                        strG13 = AbstractC3471i3.g(i5, parcel);
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                zzr zzrVar = new zzr();
                zzrVar.a = strG12;
                zzrVar.b = strG13;
                return zzrVar;
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                String strG14 = null;
                String strG15 = null;
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    char c5 = (char) i6;
                    if (c5 == 2) {
                        strG14 = AbstractC3471i3.g(i6, parcel);
                    } else if (c5 != 3) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        strG15 = AbstractC3471i3.g(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                zzs zzsVar = new zzs();
                zzsVar.a = strG14;
                zzsVar.b = strG15;
                return zzsVar;
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                int iO3 = 0;
                String strG16 = null;
                String strG17 = null;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    char c6 = (char) i7;
                    if (c6 == 2) {
                        strG16 = AbstractC3471i3.g(i7, parcel);
                    } else if (c6 == 3) {
                        strG17 = AbstractC3471i3.g(i7, parcel);
                    } else if (c6 != 4) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        iO3 = AbstractC3471i3.o(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                zzt zztVar = new zzt();
                zztVar.a = strG16;
                zztVar.b = strG17;
                zztVar.c = iO3;
                return zztVar;
            case 7:
                int iS8 = AbstractC3471i3.s(parcel);
                int iO4 = 0;
                boolean zM = false;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    char c7 = (char) i8;
                    if (c7 == 2) {
                        iO4 = AbstractC3471i3.o(i8, parcel);
                    } else if (c7 != 3) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        zM = AbstractC3471i3.m(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                zzah zzahVar = new zzah();
                zzahVar.a = iO4;
                zzahVar.b = zM;
                return zzahVar;
            case 8:
                int iS9 = AbstractC3471i3.s(parcel);
                int iO5 = 0;
                int iO6 = 0;
                int iO7 = 0;
                int iO8 = 0;
                long jP = 0;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    char c8 = (char) i9;
                    if (c8 == 2) {
                        iO5 = AbstractC3471i3.o(i9, parcel);
                    } else if (c8 == 3) {
                        iO6 = AbstractC3471i3.o(i9, parcel);
                    } else if (c8 == 4) {
                        iO7 = AbstractC3471i3.o(i9, parcel);
                    } else if (c8 == 5) {
                        jP = AbstractC3471i3.p(i9, parcel);
                    } else if (c8 != 6) {
                        AbstractC3471i3.r(i9, parcel);
                    } else {
                        iO8 = AbstractC3471i3.o(i9, parcel);
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new zzan(iO5, jP, iO6, iO7, iO8);
            case 9:
                int iS10 = AbstractC3471i3.s(parcel);
                String[] strArrH = null;
                int iO9 = 0;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    char c9 = (char) i10;
                    if (c9 == 2) {
                        iO9 = AbstractC3471i3.o(i10, parcel);
                    } else if (c9 != 3) {
                        AbstractC3471i3.r(i10, parcel);
                    } else {
                        strArrH = AbstractC3471i3.h(i10, parcel);
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                zzi zziVar = new zzi();
                zziVar.a = iO9;
                zziVar.b = strArrH;
                return zziVar;
            case 10:
                int iS11 = AbstractC3471i3.s(parcel);
                double d3 = 0.0d;
                int iO10 = 0;
                boolean zM2 = false;
                String strG18 = null;
                String strG19 = null;
                Point[] pointArr = null;
                zzn zznVar2 = null;
                zzq zzqVar2 = null;
                zzr zzrVar2 = null;
                zzt zztVar2 = null;
                byte[] bArrD = null;
                zzo zzoVar2 = null;
                zzs zzsVar2 = null;
                zzk zzkVar = null;
                zzl zzlVar = null;
                zzm zzmVar = null;
                int iO11 = 0;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    zzt zztVar3 = zztVar2;
                    switch ((char) i11) {
                        case 2:
                            iO10 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 3:
                            strG18 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 4:
                            strG19 = AbstractC3471i3.g(i11, parcel);
                            break;
                        case 5:
                            iO11 = AbstractC3471i3.o(i11, parcel);
                            break;
                        case 6:
                            pointArr = (Point[]) AbstractC3471i3.j(parcel, i11, Point.CREATOR);
                            break;
                        case 7:
                            zznVar2 = (zzn) AbstractC3471i3.f(parcel, i11, zzn.CREATOR);
                            break;
                        case '\b':
                            zzqVar2 = (zzq) AbstractC3471i3.f(parcel, i11, zzq.CREATOR);
                            break;
                        case '\t':
                            zzrVar2 = (zzr) AbstractC3471i3.f(parcel, i11, zzr.CREATOR);
                            break;
                        case '\n':
                            zztVar2 = (zzt) AbstractC3471i3.f(parcel, i11, zzt.CREATOR);
                            continue;
                        case 11:
                            zzsVar2 = (zzs) AbstractC3471i3.f(parcel, i11, zzs.CREATOR);
                            break;
                        case '\f':
                            zzoVar2 = (zzo) AbstractC3471i3.f(parcel, i11, zzo.CREATOR);
                            break;
                        case '\r':
                            zzkVar = (zzk) AbstractC3471i3.f(parcel, i11, zzk.CREATOR);
                            break;
                        case 14:
                            zzlVar = (zzl) AbstractC3471i3.f(parcel, i11, zzl.CREATOR);
                            break;
                        case 15:
                            zzmVar = (zzm) AbstractC3471i3.f(parcel, i11, zzm.CREATOR);
                            break;
                        case 16:
                            bArrD = AbstractC3471i3.d(i11, parcel);
                            break;
                        case 17:
                            zM2 = AbstractC3471i3.m(i11, parcel);
                            break;
                        case 18:
                            AbstractC3471i3.t(parcel, i11, 8);
                            d3 = parcel.readDouble();
                            break;
                        default:
                            AbstractC3471i3.r(i11, parcel);
                            break;
                    }
                    zztVar2 = zztVar3;
                }
                AbstractC3471i3.l(iS11, parcel);
                zzu zzuVar = new zzu();
                zzuVar.a = iO10;
                zzuVar.b = strG18;
                zzuVar.o = bArrD;
                zzuVar.c = strG19;
                zzuVar.d = iO11;
                zzuVar.e = pointArr;
                zzuVar.p = zM2;
                zzuVar.q = d3;
                zzuVar.f = zznVar2;
                zzuVar.g = zzqVar2;
                zzuVar.h = zzrVar2;
                zzuVar.i = zztVar2;
                zzuVar.j = zzsVar2;
                zzuVar.k = zzoVar2;
                zzuVar.l = zzkVar;
                zzuVar.m = zzlVar;
                zzuVar.n = zzmVar;
                return zzuVar;
            case 11:
                int iS12 = AbstractC3471i3.s(parcel);
                String strG20 = null;
                int iO12 = 0;
                int iO13 = 0;
                int iO14 = 0;
                int iO15 = 0;
                int iO16 = 0;
                int iO17 = 0;
                boolean zM3 = false;
                while (parcel.dataPosition() < iS12) {
                    int i12 = parcel.readInt();
                    switch ((char) i12) {
                        case 2:
                            iO12 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case 3:
                            iO13 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case 4:
                            iO14 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case 5:
                            iO15 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case 6:
                            iO16 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case 7:
                            iO17 = AbstractC3471i3.o(i12, parcel);
                            break;
                        case '\b':
                            zM3 = AbstractC3471i3.m(i12, parcel);
                            break;
                        case '\t':
                            strG20 = AbstractC3471i3.g(i12, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i12, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS12, parcel);
                zzj zzjVar = new zzj();
                zzjVar.a = iO12;
                zzjVar.b = iO13;
                zzjVar.c = iO14;
                zzjVar.d = iO15;
                zzjVar.e = iO16;
                zzjVar.f = iO17;
                zzjVar.g = zM3;
                zzjVar.h = strG20;
                return zzjVar;
            case 12:
                int iS13 = AbstractC3471i3.s(parcel);
                String strG21 = null;
                String strG22 = null;
                String strG23 = null;
                String strG24 = null;
                String strG25 = null;
                zzj zzjVar2 = null;
                zzj zzjVar3 = null;
                while (parcel.dataPosition() < iS13) {
                    int i13 = parcel.readInt();
                    switch ((char) i13) {
                        case 2:
                            strG21 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case 3:
                            strG22 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case 4:
                            strG23 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case 5:
                            strG24 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case 6:
                            strG25 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case 7:
                            zzjVar2 = (zzj) AbstractC3471i3.f(parcel, i13, zzj.CREATOR);
                            break;
                        case '\b':
                            zzjVar3 = (zzj) AbstractC3471i3.f(parcel, i13, zzj.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i13, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                zzk zzkVar2 = new zzk();
                zzkVar2.a = strG21;
                zzkVar2.b = strG22;
                zzkVar2.c = strG23;
                zzkVar2.d = strG24;
                zzkVar2.e = strG25;
                zzkVar2.f = zzjVar2;
                zzkVar2.g = zzjVar3;
                return zzkVar2;
            case 13:
                int iS14 = AbstractC3471i3.s(parcel);
                String[] strArrH2 = null;
                int iO18 = 0;
                while (parcel.dataPosition() < iS14) {
                    int i14 = parcel.readInt();
                    char c10 = (char) i14;
                    if (c10 == 1) {
                        iO18 = AbstractC3471i3.o(i14, parcel);
                    } else if (c10 != 2) {
                        AbstractC3471i3.r(i14, parcel);
                    } else {
                        strArrH2 = AbstractC3471i3.h(i14, parcel);
                    }
                }
                AbstractC3471i3.l(iS14, parcel);
                return new zzxp(strArrH2, iO18);
            case 14:
                int iS15 = AbstractC3471i3.s(parcel);
                zzp zzpVar2 = null;
                String strG26 = null;
                String strG27 = null;
                zzq[] zzqVarArr = null;
                zzn[] zznVarArr = null;
                String[] strArrH3 = null;
                zzi[] zziVarArr = null;
                while (parcel.dataPosition() < iS15) {
                    int i15 = parcel.readInt();
                    switch ((char) i15) {
                        case 2:
                            zzpVar2 = (zzp) AbstractC3471i3.f(parcel, i15, zzp.CREATOR);
                            break;
                        case 3:
                            strG26 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case 4:
                            strG27 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case 5:
                            zzqVarArr = (zzq[]) AbstractC3471i3.j(parcel, i15, zzq.CREATOR);
                            break;
                        case 6:
                            zznVarArr = (zzn[]) AbstractC3471i3.j(parcel, i15, zzn.CREATOR);
                            break;
                        case 7:
                            strArrH3 = AbstractC3471i3.h(i15, parcel);
                            break;
                        case '\b':
                            zziVarArr = (zzi[]) AbstractC3471i3.j(parcel, i15, zzi.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i15, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS15, parcel);
                zzl zzlVar2 = new zzl();
                zzlVar2.a = zzpVar2;
                zzlVar2.b = strG26;
                zzlVar2.c = strG27;
                zzlVar2.d = zzqVarArr;
                zzlVar2.e = zznVarArr;
                zzlVar2.f = strArrH3;
                zzlVar2.g = zziVarArr;
                return zzlVar2;
            case 15:
                int iS16 = AbstractC3471i3.s(parcel);
                String strG28 = null;
                String strG29 = null;
                byte[] bArrD2 = null;
                Point[] pointArr2 = null;
                zzxu zzxuVar = null;
                zzxx zzxxVar = null;
                zzxy zzxyVar = null;
                zzya zzyaVar = null;
                zzxz zzxzVar = null;
                zzxv zzxvVar = null;
                zzxr zzxrVar = null;
                zzxs zzxsVar = null;
                zzxt zzxtVar = null;
                int iO19 = 0;
                int iO20 = 0;
                while (parcel.dataPosition() < iS16) {
                    int i16 = parcel.readInt();
                    switch ((char) i16) {
                        case 1:
                            iO19 = AbstractC3471i3.o(i16, parcel);
                            break;
                        case 2:
                            strG28 = AbstractC3471i3.g(i16, parcel);
                            break;
                        case 3:
                            strG29 = AbstractC3471i3.g(i16, parcel);
                            break;
                        case 4:
                            bArrD2 = AbstractC3471i3.d(i16, parcel);
                            break;
                        case 5:
                            pointArr2 = (Point[]) AbstractC3471i3.j(parcel, i16, Point.CREATOR);
                            break;
                        case 6:
                            iO20 = AbstractC3471i3.o(i16, parcel);
                            break;
                        case 7:
                            zzxuVar = (zzxu) AbstractC3471i3.f(parcel, i16, zzxu.CREATOR);
                            break;
                        case '\b':
                            zzxxVar = (zzxx) AbstractC3471i3.f(parcel, i16, zzxx.CREATOR);
                            break;
                        case '\t':
                            zzxyVar = (zzxy) AbstractC3471i3.f(parcel, i16, zzxy.CREATOR);
                            break;
                        case '\n':
                            zzyaVar = (zzya) AbstractC3471i3.f(parcel, i16, zzya.CREATOR);
                            break;
                        case 11:
                            zzxzVar = (zzxz) AbstractC3471i3.f(parcel, i16, zzxz.CREATOR);
                            break;
                        case '\f':
                            zzxvVar = (zzxv) AbstractC3471i3.f(parcel, i16, zzxv.CREATOR);
                            break;
                        case '\r':
                            zzxrVar = (zzxr) AbstractC3471i3.f(parcel, i16, zzxr.CREATOR);
                            break;
                        case 14:
                            zzxsVar = (zzxs) AbstractC3471i3.f(parcel, i16, zzxs.CREATOR);
                            break;
                        case 15:
                            zzxtVar = (zzxt) AbstractC3471i3.f(parcel, i16, zzxt.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i16, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS16, parcel);
                return new zzyb(iO19, strG28, strG29, bArrD2, pointArr2, iO20, zzxuVar, zzxxVar, zzxyVar, zzyaVar, zzxzVar, zzxvVar, zzxrVar, zzxsVar, zzxtVar);
            case 16:
                int iS17 = AbstractC3471i3.s(parcel);
                int iO21 = 0;
                boolean zM4 = false;
                while (parcel.dataPosition() < iS17) {
                    int i17 = parcel.readInt();
                    char c11 = (char) i17;
                    if (c11 == 1) {
                        iO21 = AbstractC3471i3.o(i17, parcel);
                    } else if (c11 != 2) {
                        AbstractC3471i3.r(i17, parcel);
                    } else {
                        zM4 = AbstractC3471i3.m(i17, parcel);
                    }
                }
                AbstractC3471i3.l(iS17, parcel);
                return new zzyd(iO21, zM4);
            case 17:
                int iS18 = AbstractC3471i3.s(parcel);
                String strG30 = null;
                int iO22 = 0;
                int iO23 = 0;
                int iO24 = 0;
                int iO25 = 0;
                int iO26 = 0;
                int iO27 = 0;
                boolean zM5 = false;
                while (parcel.dataPosition() < iS18) {
                    int i18 = parcel.readInt();
                    switch ((char) i18) {
                        case 1:
                            iO22 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 2:
                            iO23 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 3:
                            iO24 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 4:
                            iO25 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 5:
                            iO26 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 6:
                            iO27 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 7:
                            zM5 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case '\b':
                            strG30 = AbstractC3471i3.g(i18, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i18, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS18, parcel);
                return new zzxq(iO22, iO23, iO24, iO25, iO26, iO27, zM5, strG30);
            case 18:
                int iS19 = AbstractC3471i3.s(parcel);
                String strG31 = null;
                String strG32 = null;
                String strG33 = null;
                String strG34 = null;
                String strG35 = null;
                zzxq zzxqVar = null;
                zzxq zzxqVar2 = null;
                while (parcel.dataPosition() < iS19) {
                    int i19 = parcel.readInt();
                    switch ((char) i19) {
                        case 1:
                            strG31 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 2:
                            strG32 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 3:
                            strG33 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 4:
                            strG34 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 5:
                            strG35 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 6:
                            zzxqVar = (zzxq) AbstractC3471i3.f(parcel, i19, zzxq.CREATOR);
                            break;
                        case 7:
                            zzxqVar2 = (zzxq) AbstractC3471i3.f(parcel, i19, zzxq.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i19, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS19, parcel);
                return new zzxr(strG31, strG32, strG33, strG34, strG35, zzxqVar, zzxqVar2);
            case 19:
                int iS20 = AbstractC3471i3.s(parcel);
                zzxw zzxwVar = null;
                String strG36 = null;
                String strG37 = null;
                zzxx[] zzxxVarArr = null;
                zzxu[] zzxuVarArr = null;
                String[] strArrH4 = null;
                zzxp[] zzxpVarArr = null;
                while (parcel.dataPosition() < iS20) {
                    int i20 = parcel.readInt();
                    switch ((char) i20) {
                        case 1:
                            zzxwVar = (zzxw) AbstractC3471i3.f(parcel, i20, zzxw.CREATOR);
                            break;
                        case 2:
                            strG36 = AbstractC3471i3.g(i20, parcel);
                            break;
                        case 3:
                            strG37 = AbstractC3471i3.g(i20, parcel);
                            break;
                        case 4:
                            zzxxVarArr = (zzxx[]) AbstractC3471i3.j(parcel, i20, zzxx.CREATOR);
                            break;
                        case 5:
                            zzxuVarArr = (zzxu[]) AbstractC3471i3.j(parcel, i20, zzxu.CREATOR);
                            break;
                        case 6:
                            strArrH4 = AbstractC3471i3.h(i20, parcel);
                            break;
                        case 7:
                            zzxpVarArr = (zzxp[]) AbstractC3471i3.j(parcel, i20, zzxp.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i20, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS20, parcel);
                return new zzxs(zzxwVar, strG36, strG37, zzxxVarArr, zzxuVarArr, strArrH4, zzxpVarArr);
            case 20:
                int iS21 = AbstractC3471i3.s(parcel);
                String strG38 = null;
                String strG39 = null;
                String strG40 = null;
                String strG41 = null;
                String strG42 = null;
                String strG43 = null;
                String strG44 = null;
                String strG45 = null;
                String strG46 = null;
                String strG47 = null;
                String strG48 = null;
                String strG49 = null;
                String strG50 = null;
                String strG51 = null;
                while (parcel.dataPosition() < iS21) {
                    int i21 = parcel.readInt();
                    switch ((char) i21) {
                        case 1:
                            strG38 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 2:
                            strG39 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 3:
                            strG40 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 4:
                            strG41 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 5:
                            strG42 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 6:
                            strG43 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 7:
                            strG44 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case '\b':
                            strG45 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case '\t':
                            strG46 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case '\n':
                            strG47 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 11:
                            strG48 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case '\f':
                            strG49 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case '\r':
                            strG50 = AbstractC3471i3.g(i21, parcel);
                            break;
                        case 14:
                            strG51 = AbstractC3471i3.g(i21, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i21, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS21, parcel);
                return new zzxt(strG38, strG39, strG40, strG41, strG42, strG43, strG44, strG45, strG46, strG47, strG48, strG49, strG50, strG51);
            case 21:
                int iS22 = AbstractC3471i3.s(parcel);
                String strG52 = null;
                String strG53 = null;
                int iO28 = 0;
                String strG54 = null;
                while (parcel.dataPosition() < iS22) {
                    int i22 = parcel.readInt();
                    char c12 = (char) i22;
                    if (c12 == 1) {
                        iO28 = AbstractC3471i3.o(i22, parcel);
                    } else if (c12 == 2) {
                        strG52 = AbstractC3471i3.g(i22, parcel);
                    } else if (c12 == 3) {
                        strG54 = AbstractC3471i3.g(i22, parcel);
                    } else if (c12 != 4) {
                        AbstractC3471i3.r(i22, parcel);
                    } else {
                        strG53 = AbstractC3471i3.g(i22, parcel);
                    }
                }
                AbstractC3471i3.l(iS22, parcel);
                return new zzxu(strG52, iO28, strG54, strG53);
            case EventType.WINDOW_STATE /* 22 */:
                int iS23 = AbstractC3471i3.s(parcel);
                double d4 = 0.0d;
                double d5 = 0.0d;
                while (parcel.dataPosition() < iS23) {
                    int i23 = parcel.readInt();
                    char c13 = (char) i23;
                    if (c13 == 1) {
                        AbstractC3471i3.t(parcel, i23, 8);
                        d4 = parcel.readDouble();
                    } else if (c13 != 2) {
                        AbstractC3471i3.r(i23, parcel);
                    } else {
                        AbstractC3471i3.t(parcel, i23, 8);
                        d5 = parcel.readDouble();
                    }
                }
                AbstractC3471i3.l(iS23, parcel);
                return new zzxv(d4, d5);
            case EventType.AUDIO /* 23 */:
                int iS24 = AbstractC3471i3.s(parcel);
                String strG55 = null;
                String strG56 = null;
                String strG57 = null;
                String strG58 = null;
                String strG59 = null;
                String strG60 = null;
                String strG61 = null;
                while (parcel.dataPosition() < iS24) {
                    int i24 = parcel.readInt();
                    switch ((char) i24) {
                        case 1:
                            strG55 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 2:
                            strG56 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 3:
                            strG57 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 4:
                            strG58 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 5:
                            strG59 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 6:
                            strG60 = AbstractC3471i3.g(i24, parcel);
                            break;
                        case 7:
                            strG61 = AbstractC3471i3.g(i24, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i24, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS24, parcel);
                return new zzxw(strG55, strG56, strG57, strG58, strG59, strG60, strG61);
            case EventType.VIDEO /* 24 */:
                int iS25 = AbstractC3471i3.s(parcel);
                String strG62 = null;
                int iO29 = 0;
                while (parcel.dataPosition() < iS25) {
                    int i25 = parcel.readInt();
                    char c14 = (char) i25;
                    if (c14 == 1) {
                        iO29 = AbstractC3471i3.o(i25, parcel);
                    } else if (c14 != 2) {
                        AbstractC3471i3.r(i25, parcel);
                    } else {
                        strG62 = AbstractC3471i3.g(i25, parcel);
                    }
                }
                AbstractC3471i3.l(iS25, parcel);
                return new zzxx(iO29, strG62);
            case EventType.SUBS /* 25 */:
                int iS26 = AbstractC3471i3.s(parcel);
                String strG63 = null;
                String strG64 = null;
                while (parcel.dataPosition() < iS26) {
                    int i26 = parcel.readInt();
                    char c15 = (char) i26;
                    if (c15 == 1) {
                        strG63 = AbstractC3471i3.g(i26, parcel);
                    } else if (c15 != 2) {
                        AbstractC3471i3.r(i26, parcel);
                    } else {
                        strG64 = AbstractC3471i3.g(i26, parcel);
                    }
                }
                AbstractC3471i3.l(iS26, parcel);
                return new zzxy(strG63, strG64);
            case EventType.CDN /* 26 */:
                int iS27 = AbstractC3471i3.s(parcel);
                String strG65 = null;
                String strG66 = null;
                while (parcel.dataPosition() < iS27) {
                    int i27 = parcel.readInt();
                    char c16 = (char) i27;
                    if (c16 == 1) {
                        strG65 = AbstractC3471i3.g(i27, parcel);
                    } else if (c16 != 2) {
                        AbstractC3471i3.r(i27, parcel);
                    } else {
                        strG66 = AbstractC3471i3.g(i27, parcel);
                    }
                }
                AbstractC3471i3.l(iS27, parcel);
                return new zzxz(strG65, strG66);
            case 27:
                int iS28 = AbstractC3471i3.s(parcel);
                int iO30 = 0;
                String strG67 = null;
                String strG68 = null;
                while (parcel.dataPosition() < iS28) {
                    int i28 = parcel.readInt();
                    char c17 = (char) i28;
                    if (c17 == 1) {
                        strG67 = AbstractC3471i3.g(i28, parcel);
                    } else if (c17 == 2) {
                        strG68 = AbstractC3471i3.g(i28, parcel);
                    } else if (c17 != 3) {
                        AbstractC3471i3.r(i28, parcel);
                    } else {
                        iO30 = AbstractC3471i3.o(i28, parcel);
                    }
                }
                AbstractC3471i3.l(iS28, parcel);
                return new zzya(iO30, strG67, strG68);
            case 28:
                int iS29 = AbstractC3471i3.s(parcel);
                long jP2 = 0;
                int iO31 = 0;
                int iO32 = 0;
                int iO33 = 0;
                int iO34 = 0;
                while (parcel.dataPosition() < iS29) {
                    int i29 = parcel.readInt();
                    char c18 = (char) i29;
                    if (c18 == 1) {
                        iO31 = AbstractC3471i3.o(i29, parcel);
                    } else if (c18 == 2) {
                        iO32 = AbstractC3471i3.o(i29, parcel);
                    } else if (c18 == 3) {
                        iO33 = AbstractC3471i3.o(i29, parcel);
                    } else if (c18 == 4) {
                        iO34 = AbstractC3471i3.o(i29, parcel);
                    } else if (c18 != 5) {
                        AbstractC3471i3.r(i29, parcel);
                    } else {
                        jP2 = AbstractC3471i3.p(i29, parcel);
                    }
                }
                AbstractC3471i3.l(iS29, parcel);
                return new zzyu(iO31, jP2, iO32, iO33, iO34);
            default:
                int iS30 = AbstractC3471i3.s(parcel);
                String strG69 = null;
                String strG70 = null;
                String strG71 = null;
                String strG72 = null;
                String strG73 = null;
                String strG74 = null;
                String strG75 = null;
                String strG76 = null;
                String strG77 = null;
                String strG78 = null;
                String strG79 = null;
                String strG80 = null;
                String strG81 = null;
                String strG82 = null;
                while (parcel.dataPosition() < iS30) {
                    int i30 = parcel.readInt();
                    String str = strG81;
                    switch ((char) i30) {
                        case 2:
                            strG69 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 3:
                            strG70 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 4:
                            strG71 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 5:
                            strG72 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 6:
                            strG73 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 7:
                            strG74 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case '\b':
                            strG75 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case '\t':
                            strG76 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case '\n':
                            strG77 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 11:
                            strG78 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case '\f':
                            strG79 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case '\r':
                            strG80 = AbstractC3471i3.g(i30, parcel);
                            break;
                        case 14:
                            strG81 = AbstractC3471i3.g(i30, parcel);
                            continue;
                        case 15:
                            strG82 = AbstractC3471i3.g(i30, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i30, parcel);
                            break;
                    }
                    strG81 = str;
                }
                AbstractC3471i3.l(iS30, parcel);
                zzm zzmVar2 = new zzm();
                zzmVar2.a = strG69;
                zzmVar2.b = strG70;
                zzmVar2.c = strG71;
                zzmVar2.d = strG72;
                zzmVar2.e = strG73;
                zzmVar2.f = strG74;
                zzmVar2.g = strG75;
                zzmVar2.h = strG76;
                zzmVar2.i = strG77;
                zzmVar2.j = strG78;
                zzmVar2.k = strG79;
                zzmVar2.l = strG80;
                zzmVar2.m = strG81;
                zzmVar2.n = strG82;
                return zzmVar2;
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzn[i];
            case 1:
                return new zzo[i];
            case 2:
                return new zzp[i];
            case 3:
                return new zzq[i];
            case 4:
                return new zzr[i];
            case 5:
                return new zzs[i];
            case 6:
                return new zzt[i];
            case 7:
                return new zzah[i];
            case 8:
                return new zzan[i];
            case 9:
                return new zzi[i];
            case 10:
                return new zzu[i];
            case 11:
                return new zzj[i];
            case 12:
                return new zzk[i];
            case 13:
                return new zzxp[i];
            case 14:
                return new zzl[i];
            case 15:
                return new zzyb[i];
            case 16:
                return new zzyd[i];
            case 17:
                return new zzxq[i];
            case 18:
                return new zzxr[i];
            case 19:
                return new zzxs[i];
            case 20:
                return new zzxt[i];
            case 21:
                return new zzxu[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new zzxv[i];
            case EventType.AUDIO /* 23 */:
                return new zzxw[i];
            case EventType.VIDEO /* 24 */:
                return new zzxx[i];
            case EventType.SUBS /* 25 */:
                return new zzxy[i];
            case EventType.CDN /* 26 */:
                return new zzxz[i];
            case 27:
                return new zzya[i];
            case 28:
                return new zzyu[i];
            default:
                return new zzm[i];
        }
    }
}
