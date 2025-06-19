package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.K;
import com.google.android.gms.internal.fido.M;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {

    @NonNull
    public static final Parcelable.Creator<AuthenticatorAttestationResponse> CREATOR = new i(0);
    public final T a;
    public final T b;
    public final T c;
    public final String[] d;

    public AuthenticatorAttestationResponse(byte[] bArr, byte[] bArr2, byte[] bArr3, String[] strArr) {
        u.h(bArr);
        T tK = T.k(bArr.length, bArr);
        u.h(bArr2);
        T tK2 = T.k(bArr2.length, bArr2);
        u.h(bArr3);
        T tK3 = T.k(bArr3.length, bArr3);
        this.a = tK;
        this.b = tK2;
        this.c = tK3;
        u.h(strArr);
        this.d = strArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x0145 A[Catch: JSONException -> 0x0021, zzho -> 0x01a9, TRY_LEAVE, TryCatch #8 {zzho -> 0x01a9, blocks: (B:42:0x0111, B:48:0x0134, B:50:0x0145, B:55:0x015b, B:58:0x0177, B:60:0x018c, B:62:0x0191, B:65:0x01ac, B:66:0x01b1, B:67:0x01b2, B:68:0x01b9, B:73:0x01c6, B:75:0x01d3, B:77:0x01e0, B:78:0x01f5, B:79:0x01fa, B:80:0x01fb, B:81:0x0200, B:87:0x0222, B:88:0x0227), top: B:128:0x0111, outer: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0221  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final org.json.JSONObject a() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 637
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse.a():org.json.JSONObject");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticatorAttestationResponse)) {
            return false;
        }
        AuthenticatorAttestationResponse authenticatorAttestationResponse = (AuthenticatorAttestationResponse) obj;
        return u.l(this.a, authenticatorAttestationResponse.a) && u.l(this.b, authenticatorAttestationResponse.b) && u.l(this.c, authenticatorAttestationResponse.c);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(Arrays.hashCode(new Object[]{this.a})), Integer.valueOf(Arrays.hashCode(new Object[]{this.b})), Integer.valueOf(Arrays.hashCode(new Object[]{this.c}))});
    }

    public final String toString() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(getClass().getSimpleName(), 6);
        K k = M.d;
        byte[] bArrM = this.a.m();
        fVar.v("keyHandle", k.c(bArrM.length, bArrM));
        byte[] bArrM2 = this.b.m();
        fVar.v("clientDataJSON", k.c(bArrM2.length, bArrM2));
        byte[] bArrM3 = this.c.m();
        fVar.v("attestationObject", k.c(bArrM3.length, bArrM3));
        fVar.v("transports", Arrays.toString(this.d));
        return fVar.toString();
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.d(parcel, 2, this.a.m());
        AbstractC3489l3.d(parcel, 3, this.b.m());
        AbstractC3489l3.d(parcel, 4, this.c.m());
        AbstractC3489l3.i(parcel, 5, this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
