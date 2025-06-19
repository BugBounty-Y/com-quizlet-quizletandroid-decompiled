package com.google.android.gms.ads.internal;

import android.accounts.Account;
import android.app.PendingIntent;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.comscore.streaming.EventType;
import com.google.android.gms.appset.zza;
import com.google.android.gms.appset.zzc;
import com.google.android.gms.auth.api.identity.BeginSignInResult;
import com.google.android.gms.auth.api.identity.GetSignInIntentRequest;
import com.google.android.gms.auth.api.identity.SavePasswordRequest;
import com.google.android.gms.auth.api.identity.SavePasswordResult;
import com.google.android.gms.auth.api.identity.SignInCredential;
import com.google.android.gms.auth.api.identity.SignInPassword;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.auth.api.signin.SignInAccount;
import com.google.android.gms.auth.api.signin.internal.GoogleSignInOptionsExtensionParcelable;
import com.google.android.gms.auth.api.signin.internal.SignInConfiguration;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.BitmapTeleporter;
import com.google.android.gms.common.internal.ConnectionTelemetryConfiguration;
import com.google.android.gms.common.internal.GetServiceRequest;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.RootTelemetryConfiguration;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.common.internal.zat;
import com.google.android.gms.common.internal.zav;
import com.google.android.gms.common.internal.zzj;
import com.google.android.gms.common.moduleinstall.ModuleAvailabilityResponse;
import com.google.android.gms.common.moduleinstall.ModuleInstallIntentResponse;
import com.google.android.gms.common.moduleinstall.ModuleInstallResponse;
import com.google.android.gms.common.moduleinstall.internal.ApiFeatureRequest;
import com.google.android.gms.common.zzq;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class f implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    public static void a(GetServiceRequest getServiceRequest, Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(getServiceRequest.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(getServiceRequest.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(getServiceRequest.c);
        AbstractC3489l3.h(parcel, 4, getServiceRequest.d);
        AbstractC3489l3.e(parcel, 5, getServiceRequest.e);
        AbstractC3489l3.k(parcel, 6, getServiceRequest.f, i);
        AbstractC3489l3.c(parcel, 7, getServiceRequest.g);
        AbstractC3489l3.g(parcel, 8, getServiceRequest.h, i);
        AbstractC3489l3.k(parcel, 10, getServiceRequest.i, i);
        AbstractC3489l3.k(parcel, 11, getServiceRequest.j, i);
        AbstractC3489l3.m(parcel, 12, 4);
        parcel.writeInt(getServiceRequest.k ? 1 : 0);
        AbstractC3489l3.m(parcel, 13, 4);
        parcel.writeInt(getServiceRequest.l);
        boolean z = getServiceRequest.m;
        AbstractC3489l3.m(parcel, 14, 4);
        parcel.writeInt(z ? 1 : 0);
        AbstractC3489l3.h(parcel, 15, getServiceRequest.n);
        AbstractC3489l3.o(iN, parcel);
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                boolean zM = false;
                boolean zM2 = false;
                boolean zM3 = false;
                int iO = 0;
                boolean zM4 = false;
                boolean zM5 = false;
                boolean zM6 = false;
                float f = 0.0f;
                String strG = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    switch ((char) i) {
                        case 2:
                            zM = AbstractC3471i3.m(i, parcel);
                            break;
                        case 3:
                            zM2 = AbstractC3471i3.m(i, parcel);
                            break;
                        case 4:
                            strG = AbstractC3471i3.g(i, parcel);
                            break;
                        case 5:
                            zM3 = AbstractC3471i3.m(i, parcel);
                            break;
                        case 6:
                            AbstractC3471i3.t(parcel, i, 4);
                            f = parcel.readFloat();
                            break;
                        case 7:
                            iO = AbstractC3471i3.o(i, parcel);
                            break;
                        case '\b':
                            zM4 = AbstractC3471i3.m(i, parcel);
                            break;
                        case '\t':
                            zM5 = AbstractC3471i3.m(i, parcel);
                            break;
                        case '\n':
                            zM6 = AbstractC3471i3.m(i, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new zzl(zM, zM2, strG, zM3, f, iO, zM4, zM5, zM6);
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                String strG2 = null;
                String strG3 = null;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    char c = (char) i2;
                    if (c == 1) {
                        strG2 = AbstractC3471i3.g(i2, parcel);
                    } else if (c != 2) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        strG3 = AbstractC3471i3.g(i2, parcel);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new zza(strG2, strG3);
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG4 = null;
                int iO2 = 0;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    char c2 = (char) i3;
                    if (c2 == 1) {
                        strG4 = AbstractC3471i3.g(i3, parcel);
                    } else if (c2 != 2) {
                        AbstractC3471i3.r(i3, parcel);
                    } else {
                        iO2 = AbstractC3471i3.o(i3, parcel);
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new zzc(strG4, iO2);
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                PendingIntent pendingIntent = null;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    if (((char) i4) != 1) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        pendingIntent = (PendingIntent) AbstractC3471i3.f(parcel, i4, PendingIntent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new BeginSignInResult(pendingIntent);
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                int iO3 = 0;
                boolean zM7 = false;
                String strG5 = null;
                String strG6 = null;
                String strG7 = null;
                String strG8 = null;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    switch ((char) i5) {
                        case 1:
                            strG5 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 2:
                            strG6 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 3:
                            strG7 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 4:
                            strG8 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 5:
                            zM7 = AbstractC3471i3.m(i5, parcel);
                            break;
                        case 6:
                            iO3 = AbstractC3471i3.o(i5, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i5, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new GetSignInIntentRequest(iO3, strG5, strG6, strG7, strG8, zM7);
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                int iO4 = 0;
                SignInPassword signInPassword = null;
                String strG9 = null;
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    char c3 = (char) i6;
                    if (c3 == 1) {
                        signInPassword = (SignInPassword) AbstractC3471i3.f(parcel, i6, SignInPassword.CREATOR);
                    } else if (c3 == 2) {
                        strG9 = AbstractC3471i3.g(i6, parcel);
                    } else if (c3 != 3) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        iO4 = AbstractC3471i3.o(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new SavePasswordRequest(signInPassword, strG9, iO4);
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                PendingIntent pendingIntent2 = null;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    if (((char) i7) != 1) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        pendingIntent2 = (PendingIntent) AbstractC3471i3.f(parcel, i7, PendingIntent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new SavePasswordResult(pendingIntent2);
            case 7:
                int iS8 = AbstractC3471i3.s(parcel);
                String strG10 = null;
                String strG11 = null;
                String strG12 = null;
                String strG13 = null;
                Uri uri = null;
                String strG14 = null;
                String strG15 = null;
                String strG16 = null;
                PublicKeyCredential publicKeyCredential = null;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    switch ((char) i8) {
                        case 1:
                            strG10 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case 2:
                            strG11 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case 3:
                            strG12 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case 4:
                            strG13 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case 5:
                            uri = (Uri) AbstractC3471i3.f(parcel, i8, Uri.CREATOR);
                            break;
                        case 6:
                            strG14 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case 7:
                            strG15 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case '\b':
                            strG16 = AbstractC3471i3.g(i8, parcel);
                            break;
                        case '\t':
                            publicKeyCredential = (PublicKeyCredential) AbstractC3471i3.f(parcel, i8, PublicKeyCredential.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i8, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                return new SignInCredential(strG10, strG11, strG12, strG13, uri, strG14, strG15, strG16, publicKeyCredential);
            case 8:
                int iS9 = AbstractC3471i3.s(parcel);
                String strG17 = null;
                String strG18 = null;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    char c4 = (char) i9;
                    if (c4 == 1) {
                        strG17 = AbstractC3471i3.g(i9, parcel);
                    } else if (c4 != 2) {
                        AbstractC3471i3.r(i9, parcel);
                    } else {
                        strG18 = AbstractC3471i3.g(i9, parcel);
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new SignInPassword(strG17, strG18);
            case 9:
                int iS10 = AbstractC3471i3.s(parcel);
                Bundle bundleC = null;
                int iO5 = 0;
                int iO6 = 0;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    char c5 = (char) i10;
                    if (c5 == 1) {
                        iO5 = AbstractC3471i3.o(i10, parcel);
                    } else if (c5 == 2) {
                        iO6 = AbstractC3471i3.o(i10, parcel);
                    } else if (c5 != 3) {
                        AbstractC3471i3.r(i10, parcel);
                    } else {
                        bundleC = AbstractC3471i3.c(i10, parcel);
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                return new GoogleSignInOptionsExtensionParcelable(iO5, iO6, bundleC);
            case 10:
                int iS11 = AbstractC3471i3.s(parcel);
                String strG19 = null;
                GoogleSignInOptions googleSignInOptions = null;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    char c6 = (char) i11;
                    if (c6 == 2) {
                        strG19 = AbstractC3471i3.g(i11, parcel);
                    } else if (c6 != 5) {
                        AbstractC3471i3.r(i11, parcel);
                    } else {
                        googleSignInOptions = (GoogleSignInOptions) AbstractC3471i3.f(parcel, i11, GoogleSignInOptions.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS11, parcel);
                return new SignInConfiguration(strG19, googleSignInOptions);
            case 11:
                int iS12 = AbstractC3471i3.s(parcel);
                String strG20 = null;
                String strG21 = null;
                String strG22 = null;
                String strG23 = null;
                Uri uri2 = null;
                String strG24 = null;
                String strG25 = null;
                ArrayList arrayListK = null;
                String strG26 = null;
                String strG27 = null;
                long jP = 0;
                while (parcel.dataPosition() < iS12) {
                    int i12 = parcel.readInt();
                    switch ((char) i12) {
                        case 2:
                            strG20 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 3:
                            strG21 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 4:
                            strG22 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 5:
                            strG23 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case 6:
                            uri2 = (Uri) AbstractC3471i3.f(parcel, i12, Uri.CREATOR);
                            break;
                        case 7:
                            strG24 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case '\b':
                            jP = AbstractC3471i3.p(i12, parcel);
                            break;
                        case '\t':
                            strG25 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case '\n':
                            arrayListK = AbstractC3471i3.k(parcel, i12, Scope.CREATOR);
                            break;
                        case 11:
                            strG26 = AbstractC3471i3.g(i12, parcel);
                            break;
                        case '\f':
                            strG27 = AbstractC3471i3.g(i12, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i12, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS12, parcel);
                return new GoogleSignInAccount(strG20, strG21, strG22, strG23, uri2, strG24, jP, strG25, arrayListK, strG26, strG27);
            case 12:
                int iS13 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK2 = null;
                ArrayList arrayListK3 = null;
                Account account = null;
                String strG28 = null;
                String strG29 = null;
                String strG30 = null;
                int iO7 = 0;
                boolean zM8 = false;
                boolean zM9 = false;
                boolean zM10 = false;
                while (parcel.dataPosition() < iS13) {
                    int i13 = parcel.readInt();
                    switch ((char) i13) {
                        case 1:
                            iO7 = AbstractC3471i3.o(i13, parcel);
                            break;
                        case 2:
                            arrayListK3 = AbstractC3471i3.k(parcel, i13, Scope.CREATOR);
                            break;
                        case 3:
                            account = (Account) AbstractC3471i3.f(parcel, i13, Account.CREATOR);
                            break;
                        case 4:
                            zM8 = AbstractC3471i3.m(i13, parcel);
                            break;
                        case 5:
                            zM9 = AbstractC3471i3.m(i13, parcel);
                            break;
                        case 6:
                            zM10 = AbstractC3471i3.m(i13, parcel);
                            break;
                        case 7:
                            strG28 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case '\b':
                            strG29 = AbstractC3471i3.g(i13, parcel);
                            break;
                        case '\t':
                            arrayListK2 = AbstractC3471i3.k(parcel, i13, GoogleSignInOptionsExtensionParcelable.CREATOR);
                            break;
                        case '\n':
                            strG30 = AbstractC3471i3.g(i13, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i13, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                return new GoogleSignInOptions(iO7, arrayListK3, account, zM8, zM9, zM10, strG28, strG29, GoogleSignInOptions.b(arrayListK2), strG30);
            case 13:
                int iS14 = AbstractC3471i3.s(parcel);
                String strG31 = "";
                GoogleSignInAccount googleSignInAccount = null;
                String strG32 = "";
                while (parcel.dataPosition() < iS14) {
                    int i14 = parcel.readInt();
                    char c7 = (char) i14;
                    if (c7 == 4) {
                        strG31 = AbstractC3471i3.g(i14, parcel);
                    } else if (c7 == 7) {
                        googleSignInAccount = (GoogleSignInAccount) AbstractC3471i3.f(parcel, i14, GoogleSignInAccount.CREATOR);
                    } else if (c7 != '\b') {
                        AbstractC3471i3.r(i14, parcel);
                    } else {
                        strG32 = AbstractC3471i3.g(i14, parcel);
                    }
                }
                AbstractC3471i3.l(iS14, parcel);
                return new SignInAccount(strG31, googleSignInAccount, strG32);
            case 14:
                int iS15 = AbstractC3471i3.s(parcel);
                String strG33 = null;
                int iO8 = 0;
                while (parcel.dataPosition() < iS15) {
                    int i15 = parcel.readInt();
                    char c8 = (char) i15;
                    if (c8 == 1) {
                        iO8 = AbstractC3471i3.o(i15, parcel);
                    } else if (c8 != 2) {
                        AbstractC3471i3.r(i15, parcel);
                    } else {
                        strG33 = AbstractC3471i3.g(i15, parcel);
                    }
                }
                AbstractC3471i3.l(iS15, parcel);
                return new Scope(iO8, strG33);
            case 15:
                int iS16 = AbstractC3471i3.s(parcel);
                String strG34 = null;
                ConnectionResult connectionResult = null;
                int iO9 = 0;
                PendingIntent pendingIntent3 = null;
                while (parcel.dataPosition() < iS16) {
                    int i16 = parcel.readInt();
                    char c9 = (char) i16;
                    if (c9 == 1) {
                        iO9 = AbstractC3471i3.o(i16, parcel);
                    } else if (c9 == 2) {
                        strG34 = AbstractC3471i3.g(i16, parcel);
                    } else if (c9 == 3) {
                        pendingIntent3 = (PendingIntent) AbstractC3471i3.f(parcel, i16, PendingIntent.CREATOR);
                    } else if (c9 != 4) {
                        AbstractC3471i3.r(i16, parcel);
                    } else {
                        connectionResult = (ConnectionResult) AbstractC3471i3.f(parcel, i16, ConnectionResult.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS16, parcel);
                return new Status(iO9, strG34, pendingIntent3, connectionResult);
            case 16:
                int iS17 = AbstractC3471i3.s(parcel);
                int iO10 = 0;
                ParcelFileDescriptor parcelFileDescriptor = null;
                int iO11 = 0;
                while (parcel.dataPosition() < iS17) {
                    int i17 = parcel.readInt();
                    char c10 = (char) i17;
                    if (c10 == 1) {
                        iO10 = AbstractC3471i3.o(i17, parcel);
                    } else if (c10 == 2) {
                        parcelFileDescriptor = (ParcelFileDescriptor) AbstractC3471i3.f(parcel, i17, ParcelFileDescriptor.CREATOR);
                    } else if (c10 != 3) {
                        AbstractC3471i3.r(i17, parcel);
                    } else {
                        iO11 = AbstractC3471i3.o(i17, parcel);
                    }
                }
                AbstractC3471i3.l(iS17, parcel);
                return new BitmapTeleporter(iO10, parcelFileDescriptor, iO11);
            case 17:
                int iS18 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK4 = null;
                int iO12 = 0;
                while (parcel.dataPosition() < iS18) {
                    int i18 = parcel.readInt();
                    char c11 = (char) i18;
                    if (c11 == 1) {
                        iO12 = AbstractC3471i3.o(i18, parcel);
                    } else if (c11 != 2) {
                        AbstractC3471i3.r(i18, parcel);
                    } else {
                        arrayListK4 = AbstractC3471i3.k(parcel, i18, MethodInvocation.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS18, parcel);
                return new TelemetryData(iO12, arrayListK4);
            case 18:
                int iS19 = AbstractC3471i3.s(parcel);
                int iO13 = -1;
                int iO14 = 0;
                int iO15 = 0;
                int iO16 = 0;
                int iO17 = 0;
                String strG35 = null;
                String strG36 = null;
                long jP2 = 0;
                long jP3 = 0;
                while (parcel.dataPosition() < iS19) {
                    int i19 = parcel.readInt();
                    switch ((char) i19) {
                        case 1:
                            iO14 = AbstractC3471i3.o(i19, parcel);
                            break;
                        case 2:
                            iO15 = AbstractC3471i3.o(i19, parcel);
                            break;
                        case 3:
                            iO16 = AbstractC3471i3.o(i19, parcel);
                            break;
                        case 4:
                            jP2 = AbstractC3471i3.p(i19, parcel);
                            break;
                        case 5:
                            jP3 = AbstractC3471i3.p(i19, parcel);
                            break;
                        case 6:
                            strG35 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case 7:
                            strG36 = AbstractC3471i3.g(i19, parcel);
                            break;
                        case '\b':
                            iO17 = AbstractC3471i3.o(i19, parcel);
                            break;
                        case '\t':
                            iO13 = AbstractC3471i3.o(i19, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i19, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS19, parcel);
                return new MethodInvocation(iO14, iO15, iO16, jP2, jP3, strG35, strG36, iO17, iO13);
            case 19:
                int iS20 = AbstractC3471i3.s(parcel);
                Account account2 = null;
                int iO18 = 0;
                int iO19 = 0;
                GoogleSignInAccount googleSignInAccount2 = null;
                while (parcel.dataPosition() < iS20) {
                    int i20 = parcel.readInt();
                    char c12 = (char) i20;
                    if (c12 == 1) {
                        iO18 = AbstractC3471i3.o(i20, parcel);
                    } else if (c12 == 2) {
                        account2 = (Account) AbstractC3471i3.f(parcel, i20, Account.CREATOR);
                    } else if (c12 == 3) {
                        iO19 = AbstractC3471i3.o(i20, parcel);
                    } else if (c12 != 4) {
                        AbstractC3471i3.r(i20, parcel);
                    } else {
                        googleSignInAccount2 = (GoogleSignInAccount) AbstractC3471i3.f(parcel, i20, GoogleSignInAccount.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS20, parcel);
                return new zat(iO18, account2, iO19, googleSignInAccount2);
            case 20:
                int iS21 = AbstractC3471i3.s(parcel);
                int iO20 = 0;
                boolean zM11 = false;
                boolean zM12 = false;
                IBinder iBinderN = null;
                ConnectionResult connectionResult2 = null;
                while (parcel.dataPosition() < iS21) {
                    int i21 = parcel.readInt();
                    char c13 = (char) i21;
                    if (c13 == 1) {
                        iO20 = AbstractC3471i3.o(i21, parcel);
                    } else if (c13 == 2) {
                        iBinderN = AbstractC3471i3.n(i21, parcel);
                    } else if (c13 == 3) {
                        connectionResult2 = (ConnectionResult) AbstractC3471i3.f(parcel, i21, ConnectionResult.CREATOR);
                    } else if (c13 == 4) {
                        zM11 = AbstractC3471i3.m(i21, parcel);
                    } else if (c13 != 5) {
                        AbstractC3471i3.r(i21, parcel);
                    } else {
                        zM12 = AbstractC3471i3.m(i21, parcel);
                    }
                }
                AbstractC3471i3.l(iS21, parcel);
                return new zav(iO20, iBinderN, connectionResult2, zM11, zM12);
            case 21:
                int iS22 = AbstractC3471i3.s(parcel);
                int iO21 = 0;
                int iO22 = 0;
                int iO23 = 0;
                boolean zM13 = false;
                boolean zM14 = false;
                while (parcel.dataPosition() < iS22) {
                    int i22 = parcel.readInt();
                    char c14 = (char) i22;
                    if (c14 == 1) {
                        iO21 = AbstractC3471i3.o(i22, parcel);
                    } else if (c14 == 2) {
                        zM13 = AbstractC3471i3.m(i22, parcel);
                    } else if (c14 == 3) {
                        zM14 = AbstractC3471i3.m(i22, parcel);
                    } else if (c14 == 4) {
                        iO22 = AbstractC3471i3.o(i22, parcel);
                    } else if (c14 != 5) {
                        AbstractC3471i3.r(i22, parcel);
                    } else {
                        iO23 = AbstractC3471i3.o(i22, parcel);
                    }
                }
                AbstractC3471i3.l(iS22, parcel);
                return new RootTelemetryConfiguration(iO21, iO22, iO23, zM13, zM14);
            case EventType.WINDOW_STATE /* 22 */:
                int iS23 = AbstractC3471i3.s(parcel);
                Bundle bundleC2 = null;
                ConnectionTelemetryConfiguration connectionTelemetryConfiguration = null;
                int iO24 = 0;
                Feature[] featureArr = null;
                while (parcel.dataPosition() < iS23) {
                    int i23 = parcel.readInt();
                    char c15 = (char) i23;
                    if (c15 == 1) {
                        bundleC2 = AbstractC3471i3.c(i23, parcel);
                    } else if (c15 == 2) {
                        featureArr = (Feature[]) AbstractC3471i3.j(parcel, i23, Feature.CREATOR);
                    } else if (c15 == 3) {
                        iO24 = AbstractC3471i3.o(i23, parcel);
                    } else if (c15 != 4) {
                        AbstractC3471i3.r(i23, parcel);
                    } else {
                        connectionTelemetryConfiguration = (ConnectionTelemetryConfiguration) AbstractC3471i3.f(parcel, i23, ConnectionTelemetryConfiguration.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS23, parcel);
                zzj zzjVar = new zzj();
                zzjVar.a = bundleC2;
                zzjVar.b = featureArr;
                zzjVar.c = iO24;
                zzjVar.d = connectionTelemetryConfiguration;
                return zzjVar;
            case EventType.AUDIO /* 23 */:
                int iS24 = AbstractC3471i3.s(parcel);
                RootTelemetryConfiguration rootTelemetryConfiguration = null;
                int[] iArrCreateIntArray = null;
                int[] iArrCreateIntArray2 = null;
                boolean zM15 = false;
                boolean zM16 = false;
                int iO25 = 0;
                while (parcel.dataPosition() < iS24) {
                    int i24 = parcel.readInt();
                    switch ((char) i24) {
                        case 1:
                            rootTelemetryConfiguration = (RootTelemetryConfiguration) AbstractC3471i3.f(parcel, i24, RootTelemetryConfiguration.CREATOR);
                            break;
                        case 2:
                            zM15 = AbstractC3471i3.m(i24, parcel);
                            break;
                        case 3:
                            zM16 = AbstractC3471i3.m(i24, parcel);
                            break;
                        case 4:
                            int iQ = AbstractC3471i3.q(i24, parcel);
                            int iDataPosition = parcel.dataPosition();
                            if (iQ != 0) {
                                iArrCreateIntArray = parcel.createIntArray();
                                parcel.setDataPosition(iDataPosition + iQ);
                                break;
                            } else {
                                iArrCreateIntArray = null;
                                break;
                            }
                        case 5:
                            iO25 = AbstractC3471i3.o(i24, parcel);
                            break;
                        case 6:
                            int iQ2 = AbstractC3471i3.q(i24, parcel);
                            int iDataPosition2 = parcel.dataPosition();
                            if (iQ2 != 0) {
                                iArrCreateIntArray2 = parcel.createIntArray();
                                parcel.setDataPosition(iDataPosition2 + iQ2);
                                break;
                            } else {
                                iArrCreateIntArray2 = null;
                                break;
                            }
                        default:
                            AbstractC3471i3.r(i24, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS24, parcel);
                return new ConnectionTelemetryConfiguration(rootTelemetryConfiguration, zM15, zM16, iArrCreateIntArray, iO25, iArrCreateIntArray2);
            case EventType.VIDEO /* 24 */:
                int iS25 = AbstractC3471i3.s(parcel);
                Scope[] scopeArr = GetServiceRequest.o;
                Bundle bundle = new Bundle();
                Feature[] featureArr2 = GetServiceRequest.p;
                Feature[] featureArr3 = featureArr2;
                String strG37 = null;
                IBinder iBinderN2 = null;
                Account account3 = null;
                String strG38 = null;
                int iO26 = 0;
                int iO27 = 0;
                int iO28 = 0;
                boolean zM17 = false;
                int iO29 = 0;
                boolean zM18 = false;
                while (parcel.dataPosition() < iS25) {
                    int i25 = parcel.readInt();
                    switch ((char) i25) {
                        case 1:
                            iO26 = AbstractC3471i3.o(i25, parcel);
                            break;
                        case 2:
                            iO27 = AbstractC3471i3.o(i25, parcel);
                            break;
                        case 3:
                            iO28 = AbstractC3471i3.o(i25, parcel);
                            break;
                        case 4:
                            strG37 = AbstractC3471i3.g(i25, parcel);
                            break;
                        case 5:
                            iBinderN2 = AbstractC3471i3.n(i25, parcel);
                            break;
                        case 6:
                            scopeArr = (Scope[]) AbstractC3471i3.j(parcel, i25, Scope.CREATOR);
                            break;
                        case 7:
                            bundle = AbstractC3471i3.c(i25, parcel);
                            break;
                        case '\b':
                            account3 = (Account) AbstractC3471i3.f(parcel, i25, Account.CREATOR);
                            break;
                        case '\t':
                        default:
                            AbstractC3471i3.r(i25, parcel);
                            break;
                        case '\n':
                            featureArr2 = (Feature[]) AbstractC3471i3.j(parcel, i25, Feature.CREATOR);
                            break;
                        case 11:
                            featureArr3 = (Feature[]) AbstractC3471i3.j(parcel, i25, Feature.CREATOR);
                            break;
                        case '\f':
                            zM17 = AbstractC3471i3.m(i25, parcel);
                            break;
                        case '\r':
                            iO29 = AbstractC3471i3.o(i25, parcel);
                            break;
                        case 14:
                            zM18 = AbstractC3471i3.m(i25, parcel);
                            break;
                        case 15:
                            strG38 = AbstractC3471i3.g(i25, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS25, parcel);
                return new GetServiceRequest(iO26, iO27, iO28, strG37, iBinderN2, scopeArr, bundle, account3, featureArr2, featureArr3, zM17, iO29, zM18, strG38);
            case EventType.SUBS /* 25 */:
                int iS26 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK5 = null;
                String strG39 = null;
                boolean zM19 = false;
                String strG40 = null;
                while (parcel.dataPosition() < iS26) {
                    int i26 = parcel.readInt();
                    char c16 = (char) i26;
                    if (c16 == 1) {
                        arrayListK5 = AbstractC3471i3.k(parcel, i26, Feature.CREATOR);
                    } else if (c16 == 2) {
                        zM19 = AbstractC3471i3.m(i26, parcel);
                    } else if (c16 == 3) {
                        strG40 = AbstractC3471i3.g(i26, parcel);
                    } else if (c16 != 4) {
                        AbstractC3471i3.r(i26, parcel);
                    } else {
                        strG39 = AbstractC3471i3.g(i26, parcel);
                    }
                }
                AbstractC3471i3.l(iS26, parcel);
                return new ApiFeatureRequest(arrayListK5, zM19, strG40, strG39);
            case EventType.CDN /* 26 */:
                int iS27 = AbstractC3471i3.s(parcel);
                boolean zM20 = false;
                int iO30 = 0;
                while (parcel.dataPosition() < iS27) {
                    int i27 = parcel.readInt();
                    char c17 = (char) i27;
                    if (c17 == 1) {
                        zM20 = AbstractC3471i3.m(i27, parcel);
                    } else if (c17 != 2) {
                        AbstractC3471i3.r(i27, parcel);
                    } else {
                        iO30 = AbstractC3471i3.o(i27, parcel);
                    }
                }
                AbstractC3471i3.l(iS27, parcel);
                return new ModuleAvailabilityResponse(zM20, iO30);
            case 27:
                int iS28 = AbstractC3471i3.s(parcel);
                PendingIntent pendingIntent4 = null;
                while (parcel.dataPosition() < iS28) {
                    int i28 = parcel.readInt();
                    if (((char) i28) != 1) {
                        AbstractC3471i3.r(i28, parcel);
                    } else {
                        pendingIntent4 = (PendingIntent) AbstractC3471i3.f(parcel, i28, PendingIntent.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS28, parcel);
                return new ModuleInstallIntentResponse(pendingIntent4);
            case 28:
                int iS29 = AbstractC3471i3.s(parcel);
                int iO31 = 0;
                boolean zM21 = false;
                while (parcel.dataPosition() < iS29) {
                    int i29 = parcel.readInt();
                    char c18 = (char) i29;
                    if (c18 == 1) {
                        iO31 = AbstractC3471i3.o(i29, parcel);
                    } else if (c18 != 2) {
                        AbstractC3471i3.r(i29, parcel);
                    } else {
                        zM21 = AbstractC3471i3.m(i29, parcel);
                    }
                }
                AbstractC3471i3.l(iS29, parcel);
                return new ModuleInstallResponse(iO31, zM21);
            default:
                int iS30 = AbstractC3471i3.s(parcel);
                int iO32 = 0;
                boolean zM22 = false;
                while (parcel.dataPosition() < iS30) {
                    int i30 = parcel.readInt();
                    char c19 = (char) i30;
                    if (c19 == 1) {
                        iO32 = AbstractC3471i3.o(i30, parcel);
                    } else if (c19 != 2) {
                        AbstractC3471i3.r(i30, parcel);
                    } else {
                        zM22 = AbstractC3471i3.m(i30, parcel);
                    }
                }
                AbstractC3471i3.l(iS30, parcel);
                return new zzq(iO32, zM22);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new zzl[i];
            case 1:
                return new zza[i];
            case 2:
                return new zzc[i];
            case 3:
                return new BeginSignInResult[i];
            case 4:
                return new GetSignInIntentRequest[i];
            case 5:
                return new SavePasswordRequest[i];
            case 6:
                return new SavePasswordResult[i];
            case 7:
                return new SignInCredential[i];
            case 8:
                return new SignInPassword[i];
            case 9:
                return new GoogleSignInOptionsExtensionParcelable[i];
            case 10:
                return new SignInConfiguration[i];
            case 11:
                return new GoogleSignInAccount[i];
            case 12:
                return new GoogleSignInOptions[i];
            case 13:
                return new SignInAccount[i];
            case 14:
                return new Scope[i];
            case 15:
                return new Status[i];
            case 16:
                return new BitmapTeleporter[i];
            case 17:
                return new TelemetryData[i];
            case 18:
                return new MethodInvocation[i];
            case 19:
                return new zat[i];
            case 20:
                return new zav[i];
            case 21:
                return new RootTelemetryConfiguration[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new zzj[i];
            case EventType.AUDIO /* 23 */:
                return new ConnectionTelemetryConfiguration[i];
            case EventType.VIDEO /* 24 */:
                return new GetServiceRequest[i];
            case EventType.SUBS /* 25 */:
                return new ApiFeatureRequest[i];
            case EventType.CDN /* 26 */:
                return new ModuleAvailabilityResponse[i];
            case 27:
                return new ModuleInstallIntentResponse[i];
            case 28:
                return new ModuleInstallResponse[i];
            default:
                return new zzq[i];
        }
    }
}
