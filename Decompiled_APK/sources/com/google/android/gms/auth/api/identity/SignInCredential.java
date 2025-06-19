package com.google.android.gms.auth.api.identity;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

@Deprecated
/* loaded from: classes2.dex */
public final class SignInCredential extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<SignInCredential> CREATOR = new com.google.android.gms.ads.internal.f(7);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final Uri e;
    public final String f;
    public final String g;
    public final String h;
    public final PublicKeyCredential i;

    public SignInCredential(String str, String str2, String str3, String str4, Uri uri, String str5, String str6, String str7, PublicKeyCredential publicKeyCredential) {
        u.h(str);
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = uri;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = publicKeyCredential;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof SignInCredential)) {
            return false;
        }
        SignInCredential signInCredential = (SignInCredential) obj;
        return u.l(this.a, signInCredential.a) && u.l(this.b, signInCredential.b) && u.l(this.c, signInCredential.c) && u.l(this.d, signInCredential.d) && u.l(this.e, signInCredential.e) && u.l(this.f, signInCredential.f) && u.l(this.g, signInCredential.g) && u.l(this.h, signInCredential.h) && u.l(this.i, signInCredential.i);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.g(parcel, 5, this.e, i);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.h(parcel, 8, this.h);
        AbstractC3489l3.g(parcel, 9, this.i, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
