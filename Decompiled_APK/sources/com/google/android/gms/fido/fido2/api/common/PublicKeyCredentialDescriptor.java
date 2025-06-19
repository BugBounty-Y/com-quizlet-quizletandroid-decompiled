package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.internal.fido.AbstractC2937a;
import com.google.android.gms.internal.fido.AbstractC2951o;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class PublicKeyCredentialDescriptor extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<PublicKeyCredentialDescriptor> CREATOR;
    public final PublicKeyCredentialType a;
    public final T b;
    public final ArrayList c;

    public static class UnsupportedPubKeyCredDescriptorException extends Exception {
    }

    static {
        AbstractC2951o.h(2, AbstractC2937a.c, AbstractC2937a.d);
        CREATOR = new com.google.android.gms.common.i(14);
    }

    public PublicKeyCredentialDescriptor(String str, byte[] bArr, ArrayList arrayList) {
        T t = T.c;
        T tK = T.k(bArr.length, bArr);
        u.h(str);
        try {
            this.a = PublicKeyCredentialType.a(str);
            this.b = tK;
            this.c = arrayList;
        } catch (PublicKeyCredentialType.UnsupportedPublicKeyCredTypeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyCredentialDescriptor)) {
            return false;
        }
        PublicKeyCredentialDescriptor publicKeyCredentialDescriptor = (PublicKeyCredentialDescriptor) obj;
        if (!this.a.equals(publicKeyCredentialDescriptor.a) || !u.l(this.b, publicKeyCredentialDescriptor.b)) {
            return false;
        }
        ArrayList arrayList = this.c;
        ArrayList arrayList2 = publicKeyCredentialDescriptor.c;
        if (arrayList == null && arrayList2 == null) {
            return true;
        }
        return arrayList != null && arrayList2 != null && arrayList.containsAll(arrayList2) && arrayList2.containsAll(arrayList);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c});
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.a);
        String strG = com.google.android.gms.common.util.c.g(this.b.m());
        return android.support.v4.media.session.a.t(AbstractC0147y.h("PublicKeyCredentialDescriptor{\n type=", strValueOf, ", \n id=", strG, ", \n transports="), String.valueOf(this.c), "}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        this.a.getClass();
        AbstractC3489l3.h(parcel, 2, "public-key");
        AbstractC3489l3.d(parcel, 3, this.b.m());
        AbstractC3489l3.l(parcel, 4, this.c);
        AbstractC3489l3.o(iN, parcel);
    }
}
