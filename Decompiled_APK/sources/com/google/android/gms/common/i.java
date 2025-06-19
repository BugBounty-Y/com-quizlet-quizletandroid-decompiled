package com.google.android.gms.common;

import android.app.PendingIntent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.ResultReceiver;
import com.comscore.streaming.EventType;
import com.google.android.gms.fido.common.Transport;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensions;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensionsClientOutputs;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensionsCredPropsOutputs;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.FidoAppIdExtension;
import com.google.android.gms.fido.fido2.api.common.GoogleThirdPartyPaymentExtension;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.google.android.gms.fido.fido2.api.common.TokenBinding;
import com.google.android.gms.fido.fido2.api.common.UserVerificationMethodExtension;
import com.google.android.gms.fido.fido2.api.common.UserVerificationRequirement;
import com.google.android.gms.fido.fido2.api.common.UvmEntries;
import com.google.android.gms.fido.fido2.api.common.UvmEntry;
import com.google.android.gms.fido.fido2.api.common.zzab;
import com.google.android.gms.fido.fido2.api.common.zzad;
import com.google.android.gms.fido.fido2.api.common.zzai;
import com.google.android.gms.fido.fido2.api.common.zzak;
import com.google.android.gms.fido.fido2.api.common.zzaw;
import com.google.android.gms.fido.fido2.api.common.zzbc;
import com.google.android.gms.fido.fido2.api.common.zzf;
import com.google.android.gms.fido.fido2.api.common.zzh;
import com.google.android.gms.fido.fido2.api.common.zzs;
import com.google.android.gms.fido.fido2.api.common.zzu;
import com.google.android.gms.fido.fido2.api.common.zzz;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class i implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ i(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                int iS = AbstractC3471i3.s(parcel);
                PendingIntent pendingIntent = null;
                int iO = 0;
                int iO2 = 0;
                String strG = null;
                while (parcel.dataPosition() < iS) {
                    int i = parcel.readInt();
                    char c = (char) i;
                    if (c == 1) {
                        iO = AbstractC3471i3.o(i, parcel);
                    } else if (c == 2) {
                        iO2 = AbstractC3471i3.o(i, parcel);
                    } else if (c == 3) {
                        pendingIntent = (PendingIntent) AbstractC3471i3.f(parcel, i, PendingIntent.CREATOR);
                    } else if (c != 4) {
                        AbstractC3471i3.r(i, parcel);
                    } else {
                        strG = AbstractC3471i3.g(i, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new ConnectionResult(iO, iO2, pendingIntent, strG);
            case 1:
                int iS2 = AbstractC3471i3.s(parcel);
                long jP = -1;
                int iO3 = 0;
                String strG2 = null;
                while (parcel.dataPosition() < iS2) {
                    int i2 = parcel.readInt();
                    char c2 = (char) i2;
                    if (c2 == 1) {
                        strG2 = AbstractC3471i3.g(i2, parcel);
                    } else if (c2 == 2) {
                        iO3 = AbstractC3471i3.o(i2, parcel);
                    } else if (c2 != 3) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        jP = AbstractC3471i3.p(i2, parcel);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new Feature(iO3, jP, strG2);
            case 2:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG3 = null;
                IBinder iBinderN = null;
                zzq zzqVar = null;
                boolean zM = false;
                boolean zM2 = false;
                boolean zM3 = false;
                boolean zM4 = false;
                while (parcel.dataPosition() < iS3) {
                    int i3 = parcel.readInt();
                    switch ((char) i3) {
                        case 1:
                            strG3 = AbstractC3471i3.g(i3, parcel);
                            break;
                        case 2:
                            zM = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 3:
                            zM2 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 4:
                            iBinderN = AbstractC3471i3.n(i3, parcel);
                            break;
                        case 5:
                            zM3 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 6:
                            zM4 = AbstractC3471i3.m(i3, parcel);
                            break;
                        case 7:
                            zzqVar = (zzq) AbstractC3471i3.f(parcel, i3, zzq.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i3, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new zzr(strG3, zM, zM2, iBinderN, zM3, zM4, zzqVar);
            case 3:
                int iS4 = AbstractC3471i3.s(parcel);
                String strG4 = null;
                zzt zztVar = null;
                long jP2 = -1;
                boolean zM5 = false;
                int iO4 = 0;
                int iO5 = 0;
                while (parcel.dataPosition() < iS4) {
                    int i4 = parcel.readInt();
                    switch ((char) i4) {
                        case 1:
                            zM5 = AbstractC3471i3.m(i4, parcel);
                            break;
                        case 2:
                            strG4 = AbstractC3471i3.g(i4, parcel);
                            break;
                        case 3:
                            iO4 = AbstractC3471i3.o(i4, parcel);
                            break;
                        case 4:
                            iO5 = AbstractC3471i3.o(i4, parcel);
                            break;
                        case 5:
                            jP2 = AbstractC3471i3.p(i4, parcel);
                            break;
                        case 6:
                            zztVar = (zzt) AbstractC3471i3.f(parcel, i4, zzt.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i4, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new zzt(zM5, strG4, iO4, iO5, jP2, zztVar);
            case 4:
                int iS5 = AbstractC3471i3.s(parcel);
                boolean zM6 = false;
                String strG5 = null;
                IBinder iBinderN2 = null;
                boolean zM7 = false;
                while (parcel.dataPosition() < iS5) {
                    int i5 = parcel.readInt();
                    char c3 = (char) i5;
                    if (c3 == 1) {
                        strG5 = AbstractC3471i3.g(i5, parcel);
                    } else if (c3 == 2) {
                        iBinderN2 = AbstractC3471i3.n(i5, parcel);
                    } else if (c3 == 3) {
                        zM6 = AbstractC3471i3.m(i5, parcel);
                    } else if (c3 != 4) {
                        AbstractC3471i3.r(i5, parcel);
                    } else {
                        zM7 = AbstractC3471i3.m(i5, parcel);
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new zzv(strG5, iBinderN2, zM6, zM7);
            case 5:
                int iS6 = AbstractC3471i3.s(parcel);
                boolean zM8 = false;
                while (parcel.dataPosition() < iS6) {
                    int i6 = parcel.readInt();
                    if (((char) i6) != 1) {
                        AbstractC3471i3.r(i6, parcel);
                    } else {
                        zM8 = AbstractC3471i3.m(i6, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new zzz(zM8);
            case 6:
                int iS7 = AbstractC3471i3.s(parcel);
                long jP3 = 0;
                while (parcel.dataPosition() < iS7) {
                    int i7 = parcel.readInt();
                    if (((char) i7) != 1) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        jP3 = AbstractC3471i3.p(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new zzab(jP3);
            case 7:
                int iS8 = AbstractC3471i3.s(parcel);
                boolean zM9 = false;
                while (parcel.dataPosition() < iS8) {
                    int i8 = parcel.readInt();
                    if (((char) i8) != 1) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        zM9 = AbstractC3471i3.m(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS8, parcel);
                return new zzad(zM9);
            case 8:
                int iS9 = AbstractC3471i3.s(parcel);
                boolean zM10 = false;
                while (parcel.dataPosition() < iS9) {
                    int i9 = parcel.readInt();
                    if (((char) i9) != 1) {
                        AbstractC3471i3.r(i9, parcel);
                    } else {
                        zM10 = AbstractC3471i3.m(i9, parcel);
                    }
                }
                AbstractC3471i3.l(iS9, parcel);
                return new GoogleThirdPartyPaymentExtension(zM10);
            case 9:
                int iS10 = AbstractC3471i3.s(parcel);
                String strG6 = null;
                while (parcel.dataPosition() < iS10) {
                    int i10 = parcel.readInt();
                    if (((char) i10) != 1) {
                        AbstractC3471i3.r(i10, parcel);
                    } else {
                        strG6 = AbstractC3471i3.g(i10, parcel);
                    }
                }
                AbstractC3471i3.l(iS10, parcel);
                return new com.google.android.gms.fido.fido2.api.common.zzag(strG6);
            case 10:
                int iS11 = AbstractC3471i3.s(parcel);
                int iO6 = 0;
                byte[] bArrD = null;
                byte[] bArrD2 = null;
                byte[] bArrD3 = null;
                while (parcel.dataPosition() < iS11) {
                    int i11 = parcel.readInt();
                    char c4 = (char) i11;
                    if (c4 == 1) {
                        bArrD = AbstractC3471i3.d(i11, parcel);
                    } else if (c4 == 2) {
                        bArrD2 = AbstractC3471i3.d(i11, parcel);
                    } else if (c4 == 3) {
                        bArrD3 = AbstractC3471i3.d(i11, parcel);
                    } else if (c4 != 4) {
                        AbstractC3471i3.r(i11, parcel);
                    } else {
                        iO6 = AbstractC3471i3.o(i11, parcel);
                    }
                }
                AbstractC3471i3.l(iS11, parcel);
                return new zzai(bArrD == null ? null : T.k(bArrD.length, bArrD), bArrD2 == null ? null : T.k(bArrD2.length, bArrD2), bArrD3 != null ? T.k(bArrD3.length, bArrD3) : null, iO6);
            case 11:
                int iS12 = AbstractC3471i3.s(parcel);
                while (true) {
                    byte[][] bArr = null;
                    while (parcel.dataPosition() < iS12) {
                        int i12 = parcel.readInt();
                        if (((char) i12) != 1) {
                            AbstractC3471i3.r(i12, parcel);
                        } else {
                            int iQ = AbstractC3471i3.q(i12, parcel);
                            int iDataPosition = parcel.dataPosition();
                            if (iQ == 0) {
                                break;
                            }
                            int i13 = parcel.readInt();
                            byte[][] bArr2 = new byte[i13][];
                            for (int i14 = 0; i14 < i13; i14++) {
                                bArr2[i14] = parcel.createByteArray();
                            }
                            parcel.setDataPosition(iDataPosition + iQ);
                            bArr = bArr2;
                        }
                    }
                    AbstractC3471i3.l(iS12, parcel);
                    return new zzak(bArr);
                    break;
                }
            case 12:
                int iS13 = AbstractC3471i3.s(parcel);
                PublicKeyCredentialRpEntity publicKeyCredentialRpEntity = null;
                PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = null;
                byte[] bArrD4 = null;
                ArrayList arrayListK = null;
                Double dValueOf = null;
                ArrayList arrayListK2 = null;
                AuthenticatorSelectionCriteria authenticatorSelectionCriteria = null;
                Integer numValueOf = null;
                TokenBinding tokenBinding = null;
                String strG7 = null;
                AuthenticationExtensions authenticationExtensions = null;
                String strG8 = null;
                ResultReceiver resultReceiver = null;
                while (parcel.dataPosition() < iS13) {
                    int i15 = parcel.readInt();
                    switch ((char) i15) {
                        case 2:
                            publicKeyCredentialRpEntity = (PublicKeyCredentialRpEntity) AbstractC3471i3.f(parcel, i15, PublicKeyCredentialRpEntity.CREATOR);
                            break;
                        case 3:
                            publicKeyCredentialUserEntity = (PublicKeyCredentialUserEntity) AbstractC3471i3.f(parcel, i15, PublicKeyCredentialUserEntity.CREATOR);
                            break;
                        case 4:
                            bArrD4 = AbstractC3471i3.d(i15, parcel);
                            break;
                        case 5:
                            arrayListK = AbstractC3471i3.k(parcel, i15, PublicKeyCredentialParameters.CREATOR);
                            break;
                        case 6:
                            int iQ2 = AbstractC3471i3.q(i15, parcel);
                            if (iQ2 == 0) {
                                dValueOf = null;
                                break;
                            } else {
                                AbstractC3471i3.u(parcel, iQ2, 8);
                                dValueOf = Double.valueOf(parcel.readDouble());
                                break;
                            }
                        case 7:
                            arrayListK2 = AbstractC3471i3.k(parcel, i15, PublicKeyCredentialDescriptor.CREATOR);
                            break;
                        case '\b':
                            authenticatorSelectionCriteria = (AuthenticatorSelectionCriteria) AbstractC3471i3.f(parcel, i15, AuthenticatorSelectionCriteria.CREATOR);
                            break;
                        case '\t':
                            int iQ3 = AbstractC3471i3.q(i15, parcel);
                            if (iQ3 == 0) {
                                numValueOf = null;
                                break;
                            } else {
                                AbstractC3471i3.u(parcel, iQ3, 4);
                                numValueOf = Integer.valueOf(parcel.readInt());
                                break;
                            }
                        case '\n':
                            tokenBinding = (TokenBinding) AbstractC3471i3.f(parcel, i15, TokenBinding.CREATOR);
                            break;
                        case 11:
                            strG7 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case '\f':
                            authenticationExtensions = (AuthenticationExtensions) AbstractC3471i3.f(parcel, i15, AuthenticationExtensions.CREATOR);
                            break;
                        case '\r':
                            strG8 = AbstractC3471i3.g(i15, parcel);
                            break;
                        case 14:
                            resultReceiver = (ResultReceiver) AbstractC3471i3.f(parcel, i15, ResultReceiver.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i15, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS13, parcel);
                return new PublicKeyCredentialCreationOptions(publicKeyCredentialRpEntity, publicKeyCredentialUserEntity, bArrD4, arrayListK, dValueOf, arrayListK2, authenticatorSelectionCriteria, numValueOf, tokenBinding, strG7, authenticationExtensions, strG8, resultReceiver);
            case 13:
                int iS14 = AbstractC3471i3.s(parcel);
                String strG9 = null;
                String strG10 = null;
                byte[] bArrD5 = null;
                AuthenticatorAttestationResponse authenticatorAttestationResponse = null;
                AuthenticatorAssertionResponse authenticatorAssertionResponse = null;
                AuthenticatorErrorResponse authenticatorErrorResponse = null;
                AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs = null;
                String strG11 = null;
                while (parcel.dataPosition() < iS14) {
                    int i16 = parcel.readInt();
                    switch ((char) i16) {
                        case 1:
                            strG9 = AbstractC3471i3.g(i16, parcel);
                            break;
                        case 2:
                            strG10 = AbstractC3471i3.g(i16, parcel);
                            break;
                        case 3:
                            bArrD5 = AbstractC3471i3.d(i16, parcel);
                            break;
                        case 4:
                            authenticatorAttestationResponse = (AuthenticatorAttestationResponse) AbstractC3471i3.f(parcel, i16, AuthenticatorAttestationResponse.CREATOR);
                            break;
                        case 5:
                            authenticatorAssertionResponse = (AuthenticatorAssertionResponse) AbstractC3471i3.f(parcel, i16, AuthenticatorAssertionResponse.CREATOR);
                            break;
                        case 6:
                            authenticatorErrorResponse = (AuthenticatorErrorResponse) AbstractC3471i3.f(parcel, i16, AuthenticatorErrorResponse.CREATOR);
                            break;
                        case 7:
                            authenticationExtensionsClientOutputs = (AuthenticationExtensionsClientOutputs) AbstractC3471i3.f(parcel, i16, AuthenticationExtensionsClientOutputs.CREATOR);
                            break;
                        case '\b':
                            strG11 = AbstractC3471i3.g(i16, parcel);
                            break;
                        case '\t':
                            AbstractC3471i3.g(i16, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i16, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS14, parcel);
                return new PublicKeyCredential(strG9, strG10, bArrD5, authenticatorAttestationResponse, authenticatorAssertionResponse, authenticatorErrorResponse, authenticationExtensionsClientOutputs, strG11);
            case 14:
                int iS15 = AbstractC3471i3.s(parcel);
                String strG12 = null;
                byte[] bArrD6 = null;
                ArrayList arrayListK3 = null;
                while (parcel.dataPosition() < iS15) {
                    int i17 = parcel.readInt();
                    char c5 = (char) i17;
                    if (c5 == 2) {
                        strG12 = AbstractC3471i3.g(i17, parcel);
                    } else if (c5 == 3) {
                        bArrD6 = AbstractC3471i3.d(i17, parcel);
                    } else if (c5 != 4) {
                        AbstractC3471i3.r(i17, parcel);
                    } else {
                        arrayListK3 = AbstractC3471i3.k(parcel, i17, Transport.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS15, parcel);
                return new PublicKeyCredentialDescriptor(strG12, bArrD6, arrayListK3);
            case 15:
                int iS16 = AbstractC3471i3.s(parcel);
                String strG13 = null;
                Integer numValueOf2 = null;
                while (parcel.dataPosition() < iS16) {
                    int i18 = parcel.readInt();
                    char c6 = (char) i18;
                    if (c6 == 2) {
                        strG13 = AbstractC3471i3.g(i18, parcel);
                    } else if (c6 != 3) {
                        AbstractC3471i3.r(i18, parcel);
                    } else {
                        int iQ4 = AbstractC3471i3.q(i18, parcel);
                        if (iQ4 == 0) {
                            numValueOf2 = null;
                        } else {
                            AbstractC3471i3.u(parcel, iQ4, 4);
                            numValueOf2 = Integer.valueOf(parcel.readInt());
                        }
                    }
                }
                AbstractC3471i3.l(iS16, parcel);
                return new PublicKeyCredentialParameters(strG13, numValueOf2.intValue());
            case 16:
                int iS17 = AbstractC3471i3.s(parcel);
                String strG14 = null;
                String strG15 = null;
                String strG16 = null;
                while (parcel.dataPosition() < iS17) {
                    int i19 = parcel.readInt();
                    char c7 = (char) i19;
                    if (c7 == 2) {
                        strG14 = AbstractC3471i3.g(i19, parcel);
                    } else if (c7 == 3) {
                        strG15 = AbstractC3471i3.g(i19, parcel);
                    } else if (c7 != 4) {
                        AbstractC3471i3.r(i19, parcel);
                    } else {
                        strG16 = AbstractC3471i3.g(i19, parcel);
                    }
                }
                AbstractC3471i3.l(iS17, parcel);
                return new PublicKeyCredentialRpEntity(strG14, strG15, strG16);
            case 17:
                int iS18 = AbstractC3471i3.s(parcel);
                byte[] bArrD7 = null;
                String strG17 = null;
                String strG18 = null;
                String strG19 = null;
                while (parcel.dataPosition() < iS18) {
                    int i20 = parcel.readInt();
                    char c8 = (char) i20;
                    if (c8 == 2) {
                        bArrD7 = AbstractC3471i3.d(i20, parcel);
                    } else if (c8 == 3) {
                        strG17 = AbstractC3471i3.g(i20, parcel);
                    } else if (c8 == 4) {
                        strG18 = AbstractC3471i3.g(i20, parcel);
                    } else if (c8 != 5) {
                        AbstractC3471i3.r(i20, parcel);
                    } else {
                        strG19 = AbstractC3471i3.g(i20, parcel);
                    }
                }
                AbstractC3471i3.l(iS18, parcel);
                return new PublicKeyCredentialUserEntity(strG17, strG18, strG19, bArrD7);
            case 18:
                int iS19 = AbstractC3471i3.s(parcel);
                String strG20 = null;
                while (parcel.dataPosition() < iS19) {
                    int i21 = parcel.readInt();
                    if (((char) i21) != 1) {
                        AbstractC3471i3.r(i21, parcel);
                    } else {
                        strG20 = AbstractC3471i3.g(i21, parcel);
                    }
                }
                AbstractC3471i3.l(iS19, parcel);
                return new zzaw(strG20);
            case 19:
                int iS20 = AbstractC3471i3.s(parcel);
                String strG21 = null;
                String strG22 = null;
                while (parcel.dataPosition() < iS20) {
                    int i22 = parcel.readInt();
                    char c9 = (char) i22;
                    if (c9 == 2) {
                        strG21 = AbstractC3471i3.g(i22, parcel);
                    } else if (c9 != 3) {
                        AbstractC3471i3.r(i22, parcel);
                    } else {
                        strG22 = AbstractC3471i3.g(i22, parcel);
                    }
                }
                AbstractC3471i3.l(iS20, parcel);
                return new TokenBinding(strG21, strG22);
            case 20:
                int iS21 = AbstractC3471i3.s(parcel);
                boolean zM11 = false;
                while (parcel.dataPosition() < iS21) {
                    int i23 = parcel.readInt();
                    if (((char) i23) != 1) {
                        AbstractC3471i3.r(i23, parcel);
                    } else {
                        zM11 = AbstractC3471i3.m(i23, parcel);
                    }
                }
                AbstractC3471i3.l(iS21, parcel);
                return new UserVerificationMethodExtension(zM11);
            case 21:
                try {
                    return UserVerificationRequirement.a(parcel.readString());
                } catch (zzbc e) {
                    throw new RuntimeException(e);
                }
            case EventType.WINDOW_STATE /* 22 */:
                int iS22 = AbstractC3471i3.s(parcel);
                ArrayList arrayListK4 = null;
                while (parcel.dataPosition() < iS22) {
                    int i24 = parcel.readInt();
                    if (((char) i24) != 1) {
                        AbstractC3471i3.r(i24, parcel);
                    } else {
                        arrayListK4 = AbstractC3471i3.k(parcel, i24, UvmEntry.CREATOR);
                    }
                }
                AbstractC3471i3.l(iS22, parcel);
                return new UvmEntries(arrayListK4);
            case EventType.AUDIO /* 23 */:
                int iS23 = AbstractC3471i3.s(parcel);
                int iO7 = 0;
                short s = 0;
                short s2 = 0;
                while (parcel.dataPosition() < iS23) {
                    int i25 = parcel.readInt();
                    char c10 = (char) i25;
                    if (c10 == 1) {
                        iO7 = AbstractC3471i3.o(i25, parcel);
                    } else if (c10 == 2) {
                        AbstractC3471i3.t(parcel, i25, 4);
                        s = (short) parcel.readInt();
                    } else if (c10 != 3) {
                        AbstractC3471i3.r(i25, parcel);
                    } else {
                        AbstractC3471i3.t(parcel, i25, 4);
                        s2 = (short) parcel.readInt();
                    }
                }
                AbstractC3471i3.l(iS23, parcel);
                return new UvmEntry(iO7, s, s2);
            case EventType.VIDEO /* 24 */:
                int iS24 = AbstractC3471i3.s(parcel);
                UvmEntries uvmEntries = null;
                zzf zzfVar = null;
                AuthenticationExtensionsCredPropsOutputs authenticationExtensionsCredPropsOutputs = null;
                zzh zzhVar = null;
                String strG23 = null;
                while (parcel.dataPosition() < iS24) {
                    int i26 = parcel.readInt();
                    char c11 = (char) i26;
                    if (c11 == 1) {
                        uvmEntries = (UvmEntries) AbstractC3471i3.f(parcel, i26, UvmEntries.CREATOR);
                    } else if (c11 == 2) {
                        zzfVar = (zzf) AbstractC3471i3.f(parcel, i26, zzf.CREATOR);
                    } else if (c11 == 3) {
                        authenticationExtensionsCredPropsOutputs = (AuthenticationExtensionsCredPropsOutputs) AbstractC3471i3.f(parcel, i26, AuthenticationExtensionsCredPropsOutputs.CREATOR);
                    } else if (c11 == 4) {
                        zzhVar = (zzh) AbstractC3471i3.f(parcel, i26, zzh.CREATOR);
                    } else if (c11 != 5) {
                        AbstractC3471i3.r(i26, parcel);
                    } else {
                        strG23 = AbstractC3471i3.g(i26, parcel);
                    }
                }
                AbstractC3471i3.l(iS24, parcel);
                return new AuthenticationExtensionsClientOutputs(uvmEntries, zzfVar, authenticationExtensionsCredPropsOutputs, zzhVar, strG23);
            case EventType.SUBS /* 25 */:
                int iS25 = AbstractC3471i3.s(parcel);
                FidoAppIdExtension fidoAppIdExtension = null;
                zzs zzsVar = null;
                UserVerificationMethodExtension userVerificationMethodExtension = null;
                zzz zzzVar = null;
                zzab zzabVar = null;
                zzad zzadVar = null;
                zzu zzuVar = null;
                com.google.android.gms.fido.fido2.api.common.zzag zzagVar = null;
                GoogleThirdPartyPaymentExtension googleThirdPartyPaymentExtension = null;
                zzak zzakVar = null;
                zzaw zzawVar = null;
                zzai zzaiVar = null;
                while (parcel.dataPosition() < iS25) {
                    int i27 = parcel.readInt();
                    switch ((char) i27) {
                        case 2:
                            fidoAppIdExtension = (FidoAppIdExtension) AbstractC3471i3.f(parcel, i27, FidoAppIdExtension.CREATOR);
                            break;
                        case 3:
                            zzsVar = (zzs) AbstractC3471i3.f(parcel, i27, zzs.CREATOR);
                            break;
                        case 4:
                            userVerificationMethodExtension = (UserVerificationMethodExtension) AbstractC3471i3.f(parcel, i27, UserVerificationMethodExtension.CREATOR);
                            break;
                        case 5:
                            zzzVar = (zzz) AbstractC3471i3.f(parcel, i27, zzz.CREATOR);
                            break;
                        case 6:
                            zzabVar = (zzab) AbstractC3471i3.f(parcel, i27, zzab.CREATOR);
                            break;
                        case 7:
                            zzadVar = (zzad) AbstractC3471i3.f(parcel, i27, zzad.CREATOR);
                            break;
                        case '\b':
                            zzuVar = (zzu) AbstractC3471i3.f(parcel, i27, zzu.CREATOR);
                            break;
                        case '\t':
                            zzagVar = (com.google.android.gms.fido.fido2.api.common.zzag) AbstractC3471i3.f(parcel, i27, com.google.android.gms.fido.fido2.api.common.zzag.CREATOR);
                            break;
                        case '\n':
                            googleThirdPartyPaymentExtension = (GoogleThirdPartyPaymentExtension) AbstractC3471i3.f(parcel, i27, GoogleThirdPartyPaymentExtension.CREATOR);
                            break;
                        case 11:
                            zzakVar = (zzak) AbstractC3471i3.f(parcel, i27, zzak.CREATOR);
                            break;
                        case '\f':
                            zzawVar = (zzaw) AbstractC3471i3.f(parcel, i27, zzaw.CREATOR);
                            break;
                        case '\r':
                            zzaiVar = (zzai) AbstractC3471i3.f(parcel, i27, zzai.CREATOR);
                            break;
                        default:
                            AbstractC3471i3.r(i27, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS25, parcel);
                return new AuthenticationExtensions(fidoAppIdExtension, zzsVar, userVerificationMethodExtension, zzzVar, zzabVar, zzadVar, zzuVar, zzagVar, googleThirdPartyPaymentExtension, zzakVar, zzawVar, zzaiVar);
            case EventType.CDN /* 26 */:
                int iS26 = AbstractC3471i3.s(parcel);
                boolean zM12 = false;
                while (parcel.dataPosition() < iS26) {
                    int i28 = parcel.readInt();
                    if (((char) i28) != 1) {
                        AbstractC3471i3.r(i28, parcel);
                    } else {
                        zM12 = AbstractC3471i3.m(i28, parcel);
                    }
                }
                AbstractC3471i3.l(iS26, parcel);
                return new AuthenticationExtensionsCredPropsOutputs(zM12);
            case 27:
                int iS27 = AbstractC3471i3.s(parcel);
                byte[] bArrD8 = null;
                byte[] bArrD9 = null;
                while (parcel.dataPosition() < iS27) {
                    int i29 = parcel.readInt();
                    char c12 = (char) i29;
                    if (c12 == 1) {
                        bArrD8 = AbstractC3471i3.d(i29, parcel);
                    } else if (c12 != 2) {
                        AbstractC3471i3.r(i29, parcel);
                    } else {
                        bArrD9 = AbstractC3471i3.d(i29, parcel);
                    }
                }
                AbstractC3471i3.l(iS27, parcel);
                return new zzf(bArrD8 == null ? null : T.k(bArrD8.length, bArrD8), bArrD9 != null ? T.k(bArrD9.length, bArrD9) : null);
            case 28:
                int iS28 = AbstractC3471i3.s(parcel);
                boolean zM13 = false;
                byte[] bArrD10 = null;
                while (parcel.dataPosition() < iS28) {
                    int i30 = parcel.readInt();
                    char c13 = (char) i30;
                    if (c13 == 1) {
                        zM13 = AbstractC3471i3.m(i30, parcel);
                    } else if (c13 != 2) {
                        AbstractC3471i3.r(i30, parcel);
                    } else {
                        bArrD10 = AbstractC3471i3.d(i30, parcel);
                    }
                }
                AbstractC3471i3.l(iS28, parcel);
                return new zzh(zM13, bArrD10 != null ? T.k(bArrD10.length, bArrD10) : null);
            default:
                int iS29 = AbstractC3471i3.s(parcel);
                byte[] bArrD11 = null;
                byte[] bArrD12 = null;
                byte[] bArrD13 = null;
                byte[] bArrD14 = null;
                byte[] bArrD15 = null;
                while (parcel.dataPosition() < iS29) {
                    int i31 = parcel.readInt();
                    char c14 = (char) i31;
                    if (c14 == 2) {
                        bArrD11 = AbstractC3471i3.d(i31, parcel);
                    } else if (c14 == 3) {
                        bArrD12 = AbstractC3471i3.d(i31, parcel);
                    } else if (c14 == 4) {
                        bArrD13 = AbstractC3471i3.d(i31, parcel);
                    } else if (c14 == 5) {
                        bArrD14 = AbstractC3471i3.d(i31, parcel);
                    } else if (c14 != 6) {
                        AbstractC3471i3.r(i31, parcel);
                    } else {
                        bArrD15 = AbstractC3471i3.d(i31, parcel);
                    }
                }
                AbstractC3471i3.l(iS29, parcel);
                return new AuthenticatorAssertionResponse(bArrD11, bArrD12, bArrD13, bArrD14, bArrD15);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new ConnectionResult[i];
            case 1:
                return new Feature[i];
            case 2:
                return new zzr[i];
            case 3:
                return new zzt[i];
            case 4:
                return new zzv[i];
            case 5:
                return new zzz[i];
            case 6:
                return new zzab[i];
            case 7:
                return new zzad[i];
            case 8:
                return new GoogleThirdPartyPaymentExtension[i];
            case 9:
                return new com.google.android.gms.fido.fido2.api.common.zzag[i];
            case 10:
                return new zzai[i];
            case 11:
                return new zzak[i];
            case 12:
                return new PublicKeyCredentialCreationOptions[i];
            case 13:
                return new PublicKeyCredential[i];
            case 14:
                return new PublicKeyCredentialDescriptor[i];
            case 15:
                return new PublicKeyCredentialParameters[i];
            case 16:
                return new PublicKeyCredentialRpEntity[i];
            case 17:
                return new PublicKeyCredentialUserEntity[i];
            case 18:
                return new zzaw[i];
            case 19:
                return new TokenBinding[i];
            case 20:
                return new UserVerificationMethodExtension[i];
            case 21:
                return new UserVerificationRequirement[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new UvmEntries[i];
            case EventType.AUDIO /* 23 */:
                return new UvmEntry[i];
            case EventType.VIDEO /* 24 */:
                return new AuthenticationExtensionsClientOutputs[i];
            case EventType.SUBS /* 25 */:
                return new AuthenticationExtensions[i];
            case EventType.CDN /* 26 */:
                return new AuthenticationExtensionsCredPropsOutputs[i];
            case 27:
                return new zzf[i];
            case 28:
                return new zzh[i];
            default:
                return new AuthenticatorAssertionResponse[i];
        }
    }
}
