package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.ErrorCode;
import com.google.android.gms.internal.fido.C2939c;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class AuthenticatorErrorResponse extends AuthenticatorResponse {

    @NonNull
    public static final Parcelable.Creator<AuthenticatorErrorResponse> CREATOR = new i(1);
    public final ErrorCode a;
    public final String b;
    public final int c;

    public AuthenticatorErrorResponse(int i, int i2, String str) {
        try {
            this.a = ErrorCode.a(i);
            this.b = str;
            this.c = i2;
        } catch (ErrorCode.UnsupportedErrorCodeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticatorErrorResponse)) {
            return false;
        }
        AuthenticatorErrorResponse authenticatorErrorResponse = (AuthenticatorErrorResponse) obj;
        return u.l(this.a, authenticatorErrorResponse.a) && u.l(this.b, authenticatorErrorResponse.b) && u.l(Integer.valueOf(this.c), Integer.valueOf(authenticatorErrorResponse.c));
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, Integer.valueOf(this.c)});
    }

    public final String toString() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(getClass().getSimpleName(), 6);
        String strValueOf = String.valueOf(this.a.a);
        C2939c c2939c = new C2939c();
        ((com.quizlet.data.repository.login.a) fVar.d).c = c2939c;
        fVar.d = c2939c;
        c2939c.b = strValueOf;
        c2939c.a = "errorCode";
        String str = this.b;
        if (str != null) {
            fVar.v("errorMessage", str);
        }
        return fVar.toString();
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        int i2 = this.a.a;
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(i2);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.o(iN, parcel);
    }
}
