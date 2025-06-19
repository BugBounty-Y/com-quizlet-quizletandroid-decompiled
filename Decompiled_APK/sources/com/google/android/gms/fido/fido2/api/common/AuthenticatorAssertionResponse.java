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
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class AuthenticatorAssertionResponse extends AuthenticatorResponse {

    @NonNull
    public static final Parcelable.Creator<AuthenticatorAssertionResponse> CREATOR = new com.google.android.gms.common.i(29);
    public final T a;
    public final T b;
    public final T c;
    public final T d;
    public final T e;

    public AuthenticatorAssertionResponse(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5) {
        u.h(bArr);
        T tK = T.k(bArr.length, bArr);
        u.h(bArr2);
        T tK2 = T.k(bArr2.length, bArr2);
        u.h(bArr3);
        T tK3 = T.k(bArr3.length, bArr3);
        u.h(bArr4);
        T tK4 = T.k(bArr4.length, bArr4);
        T tK5 = bArr5 == null ? null : T.k(bArr5.length, bArr5);
        this.a = tK;
        this.b = tK2;
        this.c = tK3;
        this.d = tK4;
        this.e = tK5;
    }

    public final JSONObject a() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("clientDataJSON", com.google.android.gms.common.util.c.g(this.b.m()));
            jSONObject.put("authenticatorData", com.google.android.gms.common.util.c.g(this.c.m()));
            jSONObject.put("signature", com.google.android.gms.common.util.c.g(this.d.m()));
            T t = this.e;
            if (t == null) {
                return jSONObject;
            }
            jSONObject.put("userHandle", com.google.android.gms.common.util.c.g(t == null ? null : t.m()));
            return jSONObject;
        } catch (JSONException e) {
            throw new RuntimeException("Error encoding AuthenticatorAssertionResponse to JSON object", e);
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticatorAssertionResponse)) {
            return false;
        }
        AuthenticatorAssertionResponse authenticatorAssertionResponse = (AuthenticatorAssertionResponse) obj;
        return u.l(this.a, authenticatorAssertionResponse.a) && u.l(this.b, authenticatorAssertionResponse.b) && u.l(this.c, authenticatorAssertionResponse.c) && u.l(this.d, authenticatorAssertionResponse.d) && u.l(this.e, authenticatorAssertionResponse.e);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(Arrays.hashCode(new Object[]{this.a})), Integer.valueOf(Arrays.hashCode(new Object[]{this.b})), Integer.valueOf(Arrays.hashCode(new Object[]{this.c})), Integer.valueOf(Arrays.hashCode(new Object[]{this.d})), Integer.valueOf(Arrays.hashCode(new Object[]{this.e}))});
    }

    public final String toString() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(getClass().getSimpleName(), 6);
        K k = M.d;
        byte[] bArrM = this.a.m();
        fVar.v("keyHandle", k.c(bArrM.length, bArrM));
        byte[] bArrM2 = this.b.m();
        fVar.v("clientDataJSON", k.c(bArrM2.length, bArrM2));
        byte[] bArrM3 = this.c.m();
        fVar.v("authenticatorData", k.c(bArrM3.length, bArrM3));
        byte[] bArrM4 = this.d.m();
        fVar.v("signature", k.c(bArrM4.length, bArrM4));
        T t = this.e;
        byte[] bArrM5 = t == null ? null : t.m();
        if (bArrM5 != null) {
            fVar.v("userHandle", k.c(bArrM5.length, bArrM5));
        }
        return fVar.toString();
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.d(parcel, 2, this.a.m());
        AbstractC3489l3.d(parcel, 3, this.b.m());
        AbstractC3489l3.d(parcel, 4, this.c.m());
        AbstractC3489l3.d(parcel, 5, this.d.m());
        T t = this.e;
        AbstractC3489l3.d(parcel, 6, t == null ? null : t.m());
        AbstractC3489l3.o(iN, parcel);
    }
}
