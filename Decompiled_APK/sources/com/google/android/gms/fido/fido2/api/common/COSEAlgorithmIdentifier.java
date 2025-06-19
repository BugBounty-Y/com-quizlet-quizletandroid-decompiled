package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class COSEAlgorithmIdentifier implements Parcelable {

    @NonNull
    public static final Parcelable.Creator<COSEAlgorithmIdentifier> CREATOR = new j();
    public final Enum a;

    public static class UnsupportedAlgorithmIdentifierException extends Exception {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public COSEAlgorithmIdentifier(a aVar) {
        this.a = (Enum) aVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static COSEAlgorithmIdentifier a(int i) throws UnsupportedAlgorithmIdentifierException {
        c cVar;
        if (i == -262) {
            cVar = c.RS1;
        } else {
            c[] cVarArrValues = c.values();
            int length = cVarArrValues.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    for (b bVar : b.values()) {
                        if (bVar.a == i) {
                            cVar = bVar;
                        }
                    }
                    throw new UnsupportedAlgorithmIdentifierException(AbstractC0147y.c(i, "Algorithm with COSE value ", " not supported"));
                }
                c cVar2 = cVarArrValues[i2];
                if (cVar2.a == i) {
                    cVar = cVar2;
                    break;
                }
                i2++;
            }
        }
        return new COSEAlgorithmIdentifier(cVar);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.fido.fido2.api.common.a, java.lang.Enum] */
    /* JADX WARN: Type inference failed for: r2v3, types: [com.google.android.gms.fido.fido2.api.common.a, java.lang.Enum] */
    public final boolean equals(Object obj) {
        return (obj instanceof COSEAlgorithmIdentifier) && this.a.a() == ((COSEAlgorithmIdentifier) obj).a.a();
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a});
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("COSEAlgorithmIdentifier{algorithm=", String.valueOf(this.a), "}");
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [com.google.android.gms.fido.fido2.api.common.a, java.lang.Enum] */
    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(this.a.a());
    }
}
