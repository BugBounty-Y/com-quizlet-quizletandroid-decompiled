package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import androidx.compose.ui.node.B;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.fido.j0;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class PublicKeyCredential extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<PublicKeyCredential> CREATOR = new com.google.android.gms.common.i(13);
    public final String a;
    public final String b;
    public final T c;
    public final AuthenticatorAttestationResponse d;
    public final AuthenticatorAssertionResponse e;
    public final AuthenticatorErrorResponse f;
    public final AuthenticationExtensionsClientOutputs g;
    public final String h;

    public PublicKeyCredential(String str, String str2, byte[] bArr, AuthenticatorAttestationResponse authenticatorAttestationResponse, AuthenticatorAssertionResponse authenticatorAssertionResponse, AuthenticatorErrorResponse authenticatorErrorResponse, AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs, String str3) {
        T tK = bArr == null ? null : T.k(bArr.length, bArr);
        boolean z = false;
        u.a("Must provide a response object.", (authenticatorAttestationResponse != null && authenticatorAssertionResponse == null && authenticatorErrorResponse == null) || (authenticatorAttestationResponse == null && authenticatorAssertionResponse != null && authenticatorErrorResponse == null) || (authenticatorAttestationResponse == null && authenticatorAssertionResponse == null && authenticatorErrorResponse != null));
        if (authenticatorErrorResponse != null || (str != null && tK != null)) {
            z = true;
        }
        u.a("Must provide id and rawId if not an error response.", z);
        this.a = str;
        this.b = str2;
        this.c = tK;
        this.d = authenticatorAttestationResponse;
        this.e = authenticatorAssertionResponse;
        this.f = authenticatorErrorResponse;
        this.g = authenticationExtensionsClientOutputs;
        this.h = str3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyCredential)) {
            return false;
        }
        PublicKeyCredential publicKeyCredential = (PublicKeyCredential) obj;
        return u.l(this.a, publicKeyCredential.a) && u.l(this.b, publicKeyCredential.b) && u.l(this.c, publicKeyCredential.c) && u.l(this.d, publicKeyCredential.d) && u.l(this.e, publicKeyCredential.e) && u.l(this.f, publicKeyCredential.f) && u.l(this.g, publicKeyCredential.g) && u.l(this.h, publicKeyCredential.h);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, this.e, this.d, this.f, this.g, this.h});
    }

    public final String toString() {
        T t = this.c;
        String strG = com.google.android.gms.common.util.c.g(t == null ? null : t.m());
        String strValueOf = String.valueOf(this.d);
        String strValueOf2 = String.valueOf(this.e);
        String strValueOf3 = String.valueOf(this.f);
        String strValueOf4 = String.valueOf(this.g);
        StringBuilder sb = new StringBuilder("PublicKeyCredential{\n id='");
        sb.append(this.a);
        sb.append("', \n type='");
        B.u(sb, this.b, "', \n rawId=", strG, ", \n registerResponse=");
        B.u(sb, strValueOf, ", \n signResponse=", strValueOf2, ", \n errorResponse=");
        B.u(sb, strValueOf3, ", \n extensionsClientOutputs=", strValueOf4, ", \n authenticatorAttachment='");
        return android.support.v4.media.session.a.t(sb, this.h, "'}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        j0.a.F();
        throw null;
    }
}
