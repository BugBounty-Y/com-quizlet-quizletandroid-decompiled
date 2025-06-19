package com.google.android.gms.fido.fido2.api.common;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.comscore.streaming.EventType;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.zat;
import com.google.android.gms.common.internal.zav;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import com.google.android.gms.internal.oss_licenses.zze;
import com.google.android.gms.measurement.internal.zzap;
import com.google.android.gms.measurement.internal.zzbf;
import com.google.android.gms.measurement.internal.zzbh;
import com.google.android.gms.measurement.internal.zzov;
import com.google.android.gms.measurement.internal.zzpa;
import com.google.android.gms.measurement.internal.zzpc;
import com.google.android.gms.measurement.internal.zzpe;
import com.google.android.gms.measurement.internal.zzqb;
import com.google.android.gms.measurement.internal.zzr;
import com.google.android.gms.signin.internal.zaa;
import com.google.android.gms.signin.internal.zag;
import com.google.android.gms.signin.internal.zai;
import com.google.android.gms.signin.internal.zak;
import com.google.android.material.badge.BadgeState$State;
import com.google.firebase.messaging.RemoteMessage;
import com.google.firebase.perf.metrics.Counter;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.util.Timer;
import java.util.ArrayList;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class i implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ i(int i) {
        this.a = i;
    }

    public static void a(zzbh zzbhVar, Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, zzbhVar.a);
        AbstractC3489l3.g(parcel, 3, zzbhVar.b, i);
        AbstractC3489l3.h(parcel, 4, zzbhVar.c);
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(zzbhVar.d);
        AbstractC3489l3.o(iN, parcel);
    }

    public static void b(zzqb zzqbVar, Parcel parcel) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(zzqbVar.a);
        AbstractC3489l3.h(parcel, 2, zzqbVar.b);
        AbstractC3489l3.m(parcel, 3, 8);
        parcel.writeLong(zzqbVar.c);
        Long l = zzqbVar.d;
        if (l != null) {
            AbstractC3489l3.m(parcel, 4, 8);
            parcel.writeLong(l.longValue());
        }
        AbstractC3489l3.h(parcel, 6, zzqbVar.e);
        AbstractC3489l3.h(parcel, 7, zzqbVar.f);
        Double d = zzqbVar.g;
        if (d != null) {
            AbstractC3489l3.m(parcel, 8, 8);
            parcel.writeDouble(d.doubleValue());
        }
        AbstractC3489l3.o(iN, parcel);
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Long lValueOf;
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                byte[] bArrD = null;
                byte[] bArrD2 = null;
                byte[] bArrD3 = null;
                String[] strArrH = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    char c = (char) i;
                    if (c == 2) {
                        bArrD = AbstractC3471i3.d(i, parcel);
                    } else if (c == 3) {
                        bArrD2 = AbstractC3471i3.d(i, parcel);
                    } else if (c == 4) {
                        bArrD3 = AbstractC3471i3.d(i, parcel);
                    } else if (c != 5) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        strArrH = AbstractC3471i3.h(i, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new AuthenticatorAttestationResponse(bArrD, bArrD2, bArrD3, strArrH);
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                int iO = 0;
                String strG = null;
                int iO2 = 0;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    char c2 = (char) i2;
                    if (c2 == 2) {
                        iO = AbstractC3471i3.o(i2, parcel);
                    } else if (c2 == 3) {
                        strG = AbstractC3471i3.g(i2, parcel);
                    } else if (c2 != 4) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        iO2 = AbstractC3471i3.o(i2, parcel);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new AuthenticatorErrorResponse(iO, iO2, strG);
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG2 = null;
                Boolean boolValueOf = null;
                String strG3 = null;
                String strG4 = null;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    char c3 = (char) i3;
                    if (c3 == 2) {
                        strG2 = AbstractC3471i3.g(i3, parcel);
                    } else if (c3 == 3) {
                        int iQ = AbstractC3471i3.q(i3, parcel);
                        if (iQ == 0) {
                            boolValueOf = null;
                        } else {
                            AbstractC3471i3.u(parcel, iQ, 4);
                            boolValueOf = Boolean.valueOf(parcel.readInt() != 0);
                        }
                    } else if (c3 == 4) {
                        strG3 = AbstractC3471i3.g(i3, parcel);
                    } else if (c3 != 5) {
                        AbstractC3471i3.r(i3, parcel);
                    } else {
                        strG4 = AbstractC3471i3.g(i3, parcel);
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new AuthenticatorSelectionCriteria(strG2, strG3, boolValueOf, strG4);
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                byte[] bArrD4 = null;
                byte[] bArrD5 = null;
                byte[] bArrD6 = null;
                long jP = 0;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    char c4 = (char) i4;
                    if (c4 == 1) {
                        jP = AbstractC3471i3.p(i4, parcel);
                    } else if (c4 == 2) {
                        bArrD4 = AbstractC3471i3.d(i4, parcel);
                    } else if (c4 == 3) {
                        bArrD5 = AbstractC3471i3.d(i4, parcel);
                    } else if (c4 != 4) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        bArrD6 = AbstractC3471i3.d(i4, parcel);
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new zzq(jP, bArrD4, bArrD5, bArrD6);
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK = null;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    if (((char) i5) != 1) {
                        AbstractC3471i3.r(i5, parcel);
                    } else {
                        arrayListK = AbstractC3471i3.k(parcel, i5, zzq.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new zzs(arrayListK);
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    if (((char) i6) != 1) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        AbstractC3471i3.m(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new zzu();
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                String strG5 = null;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    if (((char) i7) != 2) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        strG5 = AbstractC3471i3.g(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new FidoAppIdExtension(strG5);
            case 7:
                return new zze(parcel);
            case 8:
                int iS8 = AbstractC3471i3.s(parcel);
                long jP2 = 0;
                long jP3 = 0;
                int iO3 = 0;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    char c5 = (char) i8;
                    if (c5 == 1) {
                        jP2 = AbstractC3471i3.p(i8, parcel);
                    } else if (c5 == 2) {
                        iO3 = AbstractC3471i3.o(i8, parcel);
                    } else if (c5 != 3) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        jP3 = AbstractC3471i3.p(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                return new com.google.android.gms.measurement.internal.zzag(jP2, jP3, iO3);
            case 9:
                int iS9 = AbstractC3471i3.s(parcel);
                String strG6 = null;
                String strG7 = null;
                zzqb zzqbVar = null;
                String strG8 = null;
                zzbh zzbhVar = null;
                zzbh zzbhVar2 = null;
                zzbh zzbhVar3 = null;
                long jP4 = 0;
                long jP5 = 0;
                long jP6 = 0;
                boolean zM = false;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    switch ((char) i9) {
                        case 2:
                            strG6 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case 3:
                            strG7 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case 4:
                            zzqbVar = (zzqb) AbstractC3471i3.f(parcel, i9, zzqb.CREATOR);
                            break;
                        case 5:
                            jP4 = AbstractC3471i3.p(i9, parcel);
                            break;
                        case 6:
                            zM = AbstractC3471i3.m(i9, parcel);
                            break;
                        case 7:
                            strG8 = AbstractC3471i3.g(i9, parcel);
                            break;
                        case '\b':
                            zzbhVar = (zzbh) AbstractC3471i3.f(parcel, i9, zzbh.CREATOR);
                            break;
                        case '\t':
                            jP5 = AbstractC3471i3.p(i9, parcel);
                            break;
                        case '\n':
                            zzbhVar2 = (zzbh) AbstractC3471i3.f(parcel, i9, zzbh.CREATOR);
                            break;
                        case 11:
                            jP6 = AbstractC3471i3.p(i9, parcel);
                            break;
                        case '\f':
                            zzbhVar3 = (zzbh) AbstractC3471i3.f(parcel, i9, zzbh.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i9, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new com.google.android.gms.measurement.internal.zzai(strG6, strG7, zzqbVar, jP4, zM, strG8, zzbhVar, jP5, zzbhVar2, jP6, zzbhVar3);
            case 10:
                int iS10 = AbstractC3471i3.s(parcel);
                Bundle bundleC = null;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    if (((char) i10) != 1) {
                        AbstractC3471i3.r(i10, parcel);
                    } else {
                        bundleC = AbstractC3471i3.c(i10, parcel);
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                return new zzap(bundleC);
            case 11:
                int iS11 = AbstractC3471i3.s(parcel);
                Bundle bundleC2 = null;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    if (((char) i11) != 2) {
                        AbstractC3471i3.r(i11, parcel);
                    } else {
                        bundleC2 = AbstractC3471i3.c(i11, parcel);
                    }
                }
                AbstractC3471i3.l(iS11, parcel);
                return new zzbf(bundleC2);
            case 12:
                int iS12 = AbstractC3471i3.s(parcel);
                long jP7 = 0;
                String strG9 = null;
                zzbf zzbfVar = null;
                String strG10 = null;
                while (parcel.dataPosition() < iS12) {
                    int i12 = parcel.readInt();
                    char c6 = (char) i12;
                    if (c6 == 2) {
                        strG9 = AbstractC3471i3.g(i12, parcel);
                    } else if (c6 == 3) {
                        zzbfVar = (zzbf) AbstractC3471i3.f(parcel, i12, zzbf.CREATOR);
                    } else if (c6 == 4) {
                        strG10 = AbstractC3471i3.g(i12, parcel);
                    } else if (c6 != 5) {
                        AbstractC3471i3.r(i12, parcel);
                    } else {
                        jP7 = AbstractC3471i3.p(i12, parcel);
                    }
                }
                AbstractC3471i3.l(iS12, parcel);
                return new zzbh(strG9, zzbfVar, strG10, jP7);
            case 13:
                int iS13 = AbstractC3471i3.s(parcel);
                int iO4 = 0;
                long jP8 = 0;
                String strG11 = null;
                while (parcel.dataPosition() < iS13) {
                    int i13 = parcel.readInt();
                    char c7 = (char) i13;
                    if (c7 == 1) {
                        strG11 = AbstractC3471i3.g(i13, parcel);
                    } else if (c7 == 2) {
                        jP8 = AbstractC3471i3.p(i13, parcel);
                    } else if (c7 != 3) {
                        AbstractC3471i3.r(i13, parcel);
                    } else {
                        iO4 = AbstractC3471i3.o(i13, parcel);
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                return new zzov(iO4, jP8, strG11);
            case 14:
                int iS14 = AbstractC3471i3.s(parcel);
                byte[] bArrD7 = null;
                String strG12 = null;
                Bundle bundleC3 = null;
                String strG13 = null;
                long jP9 = 0;
                long jP10 = 0;
                int iO5 = 0;
                while (parcel.dataPosition() < iS14) {
                    int i14 = parcel.readInt();
                    switch ((char) i14) {
                        case 1:
                            jP9 = AbstractC3471i3.p(i14, parcel);
                            break;
                        case 2:
                            bArrD7 = AbstractC3471i3.d(i14, parcel);
                            break;
                        case 3:
                            strG12 = AbstractC3471i3.g(i14, parcel);
                            break;
                        case 4:
                            bundleC3 = AbstractC3471i3.c(i14, parcel);
                            break;
                        case 5:
                            iO5 = AbstractC3471i3.o(i14, parcel);
                            break;
                        case 6:
                            jP10 = AbstractC3471i3.p(i14, parcel);
                            break;
                        case 7:
                            strG13 = AbstractC3471i3.g(i14, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i14, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS14, parcel);
                return new zzpa(jP9, bArrD7, strG12, bundleC3, iO5, jP10, strG13);
            case 15:
                int iS15 = AbstractC3471i3.s(parcel);
                ArrayList arrayListE = null;
                while (parcel.dataPosition() < iS15) {
                    int i15 = parcel.readInt();
                    if (((char) i15) != 1) {
                        AbstractC3471i3.r(i15, parcel);
                    } else {
                        arrayListE = AbstractC3471i3.e(i15, parcel);
                    }
                }
                AbstractC3471i3.l(iS15, parcel);
                return new zzpc(arrayListE);
            case 16:
                int iS16 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK2 = null;
                while (parcel.dataPosition() < iS16) {
                    int i16 = parcel.readInt();
                    if (((char) i16) != 1) {
                        AbstractC3471i3.r(i16, parcel);
                    } else {
                        arrayListK2 = AbstractC3471i3.k(parcel, i16, zzpa.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS16, parcel);
                return new zzpe(arrayListK2);
            case 17:
                int iS17 = AbstractC3471i3.s(parcel);
                String strG14 = null;
                Long l = null;
                Float fValueOf = null;
                String strG15 = null;
                String strG16 = null;
                Double dValueOf = null;
                long jP11 = 0;
                int iO6 = 0;
                while (parcel.dataPosition() < iS17) {
                    int i17 = parcel.readInt();
                    switch ((char) i17) {
                        case 1:
                            iO6 = AbstractC3471i3.o(i17, parcel);
                            break;
                        case 2:
                            strG14 = AbstractC3471i3.g(i17, parcel);
                            break;
                        case 3:
                            jP11 = AbstractC3471i3.p(i17, parcel);
                            break;
                        case 4:
                            int iQ2 = AbstractC3471i3.q(i17, parcel);
                            if (iQ2 == 0) {
                                lValueOf = null;
                            } else {
                                AbstractC3471i3.u(parcel, iQ2, 8);
                                lValueOf = Long.valueOf(parcel.readLong());
                            }
                            l = lValueOf;
                            break;
                        case 5:
                            int iQ3 = AbstractC3471i3.q(i17, parcel);
                            if (iQ3 != 0) {
                                AbstractC3471i3.u(parcel, iQ3, 4);
                                fValueOf = Float.valueOf(parcel.readFloat());
                                break;
                            } else {
                                fValueOf = null;
                                break;
                            }
                        case 6:
                            strG15 = AbstractC3471i3.g(i17, parcel);
                            break;
                        case 7:
                            strG16 = AbstractC3471i3.g(i17, parcel);
                            break;
                        case '\b':
                            int iQ4 = AbstractC3471i3.q(i17, parcel);
                            if (iQ4 != 0) {
                                AbstractC3471i3.u(parcel, iQ4, 8);
                                dValueOf = Double.valueOf(parcel.readDouble());
                                break;
                            } else {
                                dValueOf = null;
                                break;
                            }
                        default:
                            AbstractC3471i3.r(i17, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS17, parcel);
                return new zzqb(iO6, strG14, jP11, l, fValueOf, strG15, strG16, dValueOf);
            case 18:
                int iS18 = AbstractC3471i3.s(parcel);
                boolean zM2 = false;
                int iO7 = 0;
                boolean zM3 = false;
                boolean zM4 = false;
                int iO8 = 0;
                int iO9 = 0;
                long jP12 = 0;
                long jP13 = 0;
                long jP14 = 0;
                long jP15 = 0;
                long jP16 = 0;
                long jP17 = 0;
                long jP18 = 0;
                String strG17 = "";
                String strG18 = strG17;
                String strG19 = strG18;
                String strG20 = strG19;
                String strG21 = null;
                String strG22 = null;
                String strG23 = null;
                String strG24 = null;
                String strG25 = null;
                String strG26 = null;
                String strG27 = null;
                Boolean boolValueOf2 = null;
                ArrayList arrayListI = null;
                String strG28 = null;
                String strG29 = null;
                String strG30 = null;
                int iO10 = 100;
                boolean zM5 = true;
                boolean zM6 = true;
                long jP19 = -2147483648L;
                while (parcel.dataPosition() < iS18) {
                    int i18 = parcel.readInt();
                    switch ((char) i18) {
                        case 2:
                            strG21 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 3:
                            strG22 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 4:
                            strG23 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 5:
                            strG24 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 6:
                            jP12 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case 7:
                            jP13 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case '\b':
                            strG25 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case '\t':
                            zM5 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case '\n':
                            zM2 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case 11:
                            jP19 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case '\f':
                            strG26 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case '\r':
                        case 17:
                        case 20:
                        case '!':
                        default:
                            AbstractC3471i3.r(i18, parcel);
                            break;
                        case 14:
                            jP14 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case 15:
                            iO7 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 16:
                            zM6 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case 18:
                            zM3 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case 19:
                            strG27 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 21:
                            int iQ5 = AbstractC3471i3.q(i18, parcel);
                            if (iQ5 != 0) {
                                AbstractC3471i3.u(parcel, iQ5, 4);
                                boolValueOf2 = Boolean.valueOf(parcel.readInt() != 0);
                                break;
                            } else {
                                boolValueOf2 = null;
                                break;
                            }
                        case EventType.WINDOW_STATE /* 22 */:
                            jP15 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case EventType.AUDIO /* 23 */:
                            arrayListI = AbstractC3471i3.i(i18, parcel);
                            break;
                        case EventType.VIDEO /* 24 */:
                            strG28 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case EventType.SUBS /* 25 */:
                            strG17 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case EventType.CDN /* 26 */:
                            strG18 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 27:
                            strG29 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case 28:
                            zM4 = AbstractC3471i3.m(i18, parcel);
                            break;
                        case 29:
                            jP16 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case 30:
                            iO10 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case 31:
                            strG19 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case ' ':
                            iO8 = AbstractC3471i3.o(i18, parcel);
                            break;
                        case '\"':
                            jP17 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case '#':
                            strG30 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case '$':
                            strG20 = AbstractC3471i3.g(i18, parcel);
                            break;
                        case '%':
                            jP18 = AbstractC3471i3.p(i18, parcel);
                            break;
                        case '&':
                            iO9 = AbstractC3471i3.o(i18, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS18, parcel);
                return new zzr(strG21, strG22, strG23, strG24, jP12, jP13, strG25, zM5, zM2, jP19, strG26, jP14, iO7, zM6, zM3, strG27, boolValueOf2, jP15, arrayListI, strG28, strG17, strG18, strG29, zM4, jP16, iO10, strG19, iO8, jP17, strG30, strG20, jP18, iO9);
            case 19:
                int iS19 = AbstractC3471i3.s(parcel);
                Intent intent = null;
                int iO11 = 0;
                int iO12 = 0;
                while (parcel.dataPosition() < iS19) {
                    int i19 = parcel.readInt();
                    char c8 = (char) i19;
                    if (c8 == 1) {
                        iO11 = AbstractC3471i3.o(i19, parcel);
                    } else if (c8 == 2) {
                        iO12 = AbstractC3471i3.o(i19, parcel);
                    } else if (c8 != 3) {
                        AbstractC3471i3.r(i19, parcel);
                    } else {
                        intent = (Intent) AbstractC3471i3.f(parcel, i19, Intent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS19, parcel);
                return new zaa(iO11, iO12, intent);
            case 20:
                int iS20 = AbstractC3471i3.s(parcel);
                ArrayList arrayListI2 = null;
                String strG31 = null;
                while (parcel.dataPosition() < iS20) {
                    int i20 = parcel.readInt();
                    char c9 = (char) i20;
                    if (c9 == 1) {
                        arrayListI2 = AbstractC3471i3.i(i20, parcel);
                    } else if (c9 != 2) {
                        AbstractC3471i3.r(i20, parcel);
                    } else {
                        strG31 = AbstractC3471i3.g(i20, parcel);
                    }
                }
                AbstractC3471i3.l(iS20, parcel);
                return new zag(arrayListI2, strG31);
            case 21:
                int iS21 = AbstractC3471i3.s(parcel);
                zat zatVar = null;
                int iO13 = 0;
                while (parcel.dataPosition() < iS21) {
                    int i21 = parcel.readInt();
                    char c10 = (char) i21;
                    if (c10 == 1) {
                        iO13 = AbstractC3471i3.o(i21, parcel);
                    } else if (c10 != 2) {
                        AbstractC3471i3.r(i21, parcel);
                    } else {
                        zatVar = (zat) AbstractC3471i3.f(parcel, i21, zat.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS21, parcel);
                return new zai(iO13, zatVar);
            case EventType.WINDOW_STATE /* 22 */:
                int iS22 = AbstractC3471i3.s(parcel);
                ConnectionResult connectionResult = null;
                int iO14 = 0;
                zav zavVar = null;
                while (parcel.dataPosition() < iS22) {
                    int i22 = parcel.readInt();
                    char c11 = (char) i22;
                    if (c11 == 1) {
                        iO14 = AbstractC3471i3.o(i22, parcel);
                    } else if (c11 == 2) {
                        connectionResult = (ConnectionResult) AbstractC3471i3.f(parcel, i22, ConnectionResult.CREATOR);
                    } else if (c11 != 3) {
                        AbstractC3471i3.r(i22, parcel);
                    } else {
                        zavVar = (zav) AbstractC3471i3.f(parcel, i22, zav.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS22, parcel);
                return new zak(iO14, connectionResult, zavVar);
            case EventType.AUDIO /* 23 */:
                BadgeState$State badgeState$State = new BadgeState$State();
                badgeState$State.i = 255;
                badgeState$State.k = -2;
                badgeState$State.l = -2;
                badgeState$State.m = -2;
                badgeState$State.t = Boolean.TRUE;
                badgeState$State.a = parcel.readInt();
                badgeState$State.b = (Integer) parcel.readSerializable();
                badgeState$State.c = (Integer) parcel.readSerializable();
                badgeState$State.d = (Integer) parcel.readSerializable();
                badgeState$State.e = (Integer) parcel.readSerializable();
                badgeState$State.f = (Integer) parcel.readSerializable();
                badgeState$State.g = (Integer) parcel.readSerializable();
                badgeState$State.h = (Integer) parcel.readSerializable();
                badgeState$State.i = parcel.readInt();
                badgeState$State.j = parcel.readString();
                badgeState$State.k = parcel.readInt();
                badgeState$State.l = parcel.readInt();
                badgeState$State.m = parcel.readInt();
                badgeState$State.o = parcel.readString();
                badgeState$State.p = parcel.readString();
                badgeState$State.q = parcel.readInt();
                badgeState$State.s = (Integer) parcel.readSerializable();
                badgeState$State.u = (Integer) parcel.readSerializable();
                badgeState$State.v = (Integer) parcel.readSerializable();
                badgeState$State.w = (Integer) parcel.readSerializable();
                badgeState$State.x = (Integer) parcel.readSerializable();
                badgeState$State.y = (Integer) parcel.readSerializable();
                badgeState$State.z = (Integer) parcel.readSerializable();
                badgeState$State.C = (Integer) parcel.readSerializable();
                badgeState$State.A = (Integer) parcel.readSerializable();
                badgeState$State.B = (Integer) parcel.readSerializable();
                badgeState$State.t = (Boolean) parcel.readSerializable();
                badgeState$State.n = (Locale) parcel.readSerializable();
                badgeState$State.D = (Boolean) parcel.readSerializable();
                return badgeState$State;
            case EventType.VIDEO /* 24 */:
                int iS23 = AbstractC3471i3.s(parcel);
                Bundle bundleC4 = null;
                while (parcel.dataPosition() < iS23) {
                    int i23 = parcel.readInt();
                    if (((char) i23) != 2) {
                        AbstractC3471i3.r(i23, parcel);
                    } else {
                        bundleC4 = AbstractC3471i3.c(i23, parcel);
                    }
                }
                AbstractC3471i3.l(iS23, parcel);
                return new RemoteMessage(bundleC4);
            case EventType.SUBS /* 25 */:
                return new Counter(parcel);
            case EventType.CDN /* 26 */:
                return new Trace(parcel, false);
            case 27:
                return new PerfSession(parcel);
            case 28:
                return new Timer(parcel.readLong(), parcel.readLong());
            default:
                return new com.onetrust.otpublishers.headless.UI.DataModels.b(parcel);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new AuthenticatorAttestationResponse[i];
            case 1:
                return new AuthenticatorErrorResponse[i];
            case 2:
                return new AuthenticatorSelectionCriteria[i];
            case 3:
                return new zzq[i];
            case 4:
                return new zzs[i];
            case 5:
                return new zzu[i];
            case 6:
                return new FidoAppIdExtension[i];
            case 7:
                return new zze[i];
            case 8:
                return new com.google.android.gms.measurement.internal.zzag[i];
            case 9:
                return new com.google.android.gms.measurement.internal.zzai[i];
            case 10:
                return new zzap[i];
            case 11:
                return new zzbf[i];
            case 12:
                return new zzbh[i];
            case 13:
                return new zzov[i];
            case 14:
                return new zzpa[i];
            case 15:
                return new zzpc[i];
            case 16:
                return new zzpe[i];
            case 17:
                return new zzqb[i];
            case 18:
                return new zzr[i];
            case 19:
                return new zaa[i];
            case 20:
                return new zag[i];
            case 21:
                return new zai[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new zak[i];
            case EventType.AUDIO /* 23 */:
                return new BadgeState$State[i];
            case EventType.VIDEO /* 24 */:
                return new RemoteMessage[i];
            case EventType.SUBS /* 25 */:
                return new Counter[i];
            case EventType.CDN /* 26 */:
                return new Trace[i];
            case 27:
                return new PerfSession[i];
            case 28:
                return new Timer[i];
            default:
                return new com.onetrust.otpublishers.headless.UI.DataModels.b[i];
        }
    }
}
