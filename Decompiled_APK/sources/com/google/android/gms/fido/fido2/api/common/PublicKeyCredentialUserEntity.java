package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class PublicKeyCredentialUserEntity extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<PublicKeyCredentialUserEntity> CREATOR = new com.google.android.gms.common.i(17);
    public final T a;
    public final String b;
    public final String c;
    public final String d;

    public PublicKeyCredentialUserEntity(String str, String str2, String str3, byte[] bArr) {
        u.h(bArr);
        this.a = T.k(bArr.length, bArr);
        u.h(str);
        this.b = str;
        this.c = str2;
        u.h(str3);
        this.d = str3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyCredentialUserEntity)) {
            return false;
        }
        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = (PublicKeyCredentialUserEntity) obj;
        return u.l(this.a, publicKeyCredentialUserEntity.a) && u.l(this.b, publicKeyCredentialUserEntity.b) && u.l(this.c, publicKeyCredentialUserEntity.c) && u.l(this.d, publicKeyCredentialUserEntity.d);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, this.d});
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("PublicKeyCredentialUserEntity{\n id=", com.google.android.gms.common.util.c.g(this.a.m()), ", \n name='");
        sbY.append(this.b);
        sbY.append("', \n icon='");
        sbY.append(this.c);
        sbY.append("', \n displayName='");
        return android.support.v4.media.session.a.t(sbY, this.d, "'}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.d(parcel, 2, this.a.m());
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.h(parcel, 5, this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
