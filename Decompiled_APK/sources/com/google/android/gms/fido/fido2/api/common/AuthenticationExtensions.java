package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class AuthenticationExtensions extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<AuthenticationExtensions> CREATOR = new com.google.android.gms.common.i(25);
    public final FidoAppIdExtension a;
    public final zzs b;
    public final UserVerificationMethodExtension c;
    public final zzz d;
    public final zzab e;
    public final zzad f;
    public final zzu g;
    public final zzag h;
    public final GoogleThirdPartyPaymentExtension i;
    public final zzak j;
    public final zzaw k;
    public final zzai l;

    public AuthenticationExtensions(FidoAppIdExtension fidoAppIdExtension, zzs zzsVar, UserVerificationMethodExtension userVerificationMethodExtension, zzz zzzVar, zzab zzabVar, zzad zzadVar, zzu zzuVar, zzag zzagVar, GoogleThirdPartyPaymentExtension googleThirdPartyPaymentExtension, zzak zzakVar, zzaw zzawVar, zzai zzaiVar) {
        this.a = fidoAppIdExtension;
        this.c = userVerificationMethodExtension;
        this.b = zzsVar;
        this.d = zzzVar;
        this.e = zzabVar;
        this.f = zzadVar;
        this.g = zzuVar;
        this.h = zzagVar;
        this.i = googleThirdPartyPaymentExtension;
        this.j = zzakVar;
        this.k = zzawVar;
        this.l = zzaiVar;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticationExtensions)) {
            return false;
        }
        AuthenticationExtensions authenticationExtensions = (AuthenticationExtensions) obj;
        return u.l(this.a, authenticationExtensions.a) && u.l(this.b, authenticationExtensions.b) && u.l(this.c, authenticationExtensions.c) && u.l(this.d, authenticationExtensions.d) && u.l(this.e, authenticationExtensions.e) && u.l(this.f, authenticationExtensions.f) && u.l(this.g, authenticationExtensions.g) && u.l(this.h, authenticationExtensions.h) && u.l(this.i, authenticationExtensions.i) && u.l(this.j, authenticationExtensions.j) && u.l(this.k, authenticationExtensions.k) && u.l(this.l, authenticationExtensions.l);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l});
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.a);
        String strValueOf2 = String.valueOf(this.b);
        String strValueOf3 = String.valueOf(this.c);
        String strValueOf4 = String.valueOf(this.d);
        String strValueOf5 = String.valueOf(this.e);
        String strValueOf6 = String.valueOf(this.f);
        String strValueOf7 = String.valueOf(this.g);
        String strValueOf8 = String.valueOf(this.h);
        String strValueOf9 = String.valueOf(this.i);
        String strValueOf10 = String.valueOf(this.j);
        String strValueOf11 = String.valueOf(this.k);
        StringBuilder sbH = AbstractC0147y.h("AuthenticationExtensions{\n fidoAppIdExtension=", strValueOf, ", \n cableAuthenticationExtension=", strValueOf2, ", \n userVerificationMethodExtension=");
        B.u(sbH, strValueOf3, ", \n googleMultiAssertionExtension=", strValueOf4, ", \n googleSessionIdExtension=");
        B.u(sbH, strValueOf5, ", \n googleSilentVerificationExtension=", strValueOf6, ", \n devicePublicKeyExtension=");
        B.u(sbH, strValueOf7, ", \n googleTunnelServerIdExtension=", strValueOf8, ", \n googleThirdPartyPaymentExtension=");
        B.u(sbH, strValueOf9, ", \n prfExtension=", strValueOf10, ", \n simpleTransactionAuthorizationExtension=");
        return android.support.v4.media.session.a.t(sbH, strValueOf11, "}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        AbstractC3489l3.g(parcel, 3, this.b, i);
        AbstractC3489l3.g(parcel, 4, this.c, i);
        AbstractC3489l3.g(parcel, 5, this.d, i);
        AbstractC3489l3.g(parcel, 6, this.e, i);
        AbstractC3489l3.g(parcel, 7, this.f, i);
        AbstractC3489l3.g(parcel, 8, this.g, i);
        AbstractC3489l3.g(parcel, 9, this.h, i);
        AbstractC3489l3.g(parcel, 10, this.i, i);
        AbstractC3489l3.g(parcel, 11, this.j, i);
        AbstractC3489l3.g(parcel, 12, this.k, i);
        AbstractC3489l3.g(parcel, 13, this.l, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
