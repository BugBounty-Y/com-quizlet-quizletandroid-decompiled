package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.ResultReceiver;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.AttestationConveyancePreference;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class PublicKeyCredentialCreationOptions extends RequestOptions {

    @NonNull
    public static final Parcelable.Creator<PublicKeyCredentialCreationOptions> CREATOR = new com.google.android.gms.common.i(12);
    public final PublicKeyCredentialRpEntity a;
    public final PublicKeyCredentialUserEntity b;
    public final byte[] c;
    public final ArrayList d;
    public final Double e;
    public final ArrayList f;
    public final AuthenticatorSelectionCriteria g;
    public final Integer h;
    public final TokenBinding i;
    public final AttestationConveyancePreference j;
    public final AuthenticationExtensions k;
    public final String l;
    public final ResultReceiver m;

    public PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity publicKeyCredentialRpEntity, PublicKeyCredentialUserEntity publicKeyCredentialUserEntity, byte[] bArr, ArrayList arrayList, Double d, ArrayList arrayList2, AuthenticatorSelectionCriteria authenticatorSelectionCriteria, Integer num, TokenBinding tokenBinding, String str, AuthenticationExtensions authenticationExtensions, String str2, ResultReceiver resultReceiver) {
        this.m = resultReceiver;
        if (str2 != null) {
            try {
                PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptionsA = a(new JSONObject(str2));
                this.a = publicKeyCredentialCreationOptionsA.a;
                this.b = publicKeyCredentialCreationOptionsA.b;
                this.c = publicKeyCredentialCreationOptionsA.c;
                this.d = publicKeyCredentialCreationOptionsA.d;
                this.e = publicKeyCredentialCreationOptionsA.e;
                this.f = publicKeyCredentialCreationOptionsA.f;
                this.g = publicKeyCredentialCreationOptionsA.g;
                this.h = publicKeyCredentialCreationOptionsA.h;
                this.i = publicKeyCredentialCreationOptionsA.i;
                this.j = publicKeyCredentialCreationOptionsA.j;
                this.k = publicKeyCredentialCreationOptionsA.k;
                this.l = str2;
                return;
            } catch (JSONException e) {
                throw new IllegalArgumentException(e);
            }
        }
        u.h(publicKeyCredentialRpEntity);
        this.a = publicKeyCredentialRpEntity;
        u.h(publicKeyCredentialUserEntity);
        this.b = publicKeyCredentialUserEntity;
        u.h(bArr);
        this.c = bArr;
        u.h(arrayList);
        this.d = arrayList;
        this.e = d;
        this.f = arrayList2;
        this.g = authenticatorSelectionCriteria;
        this.h = num;
        this.i = tokenBinding;
        if (str != null) {
            try {
                this.j = AttestationConveyancePreference.a(str);
            } catch (AttestationConveyancePreference.UnsupportedAttestationConveyancePreferenceException e2) {
                throw new IllegalArgumentException(e2);
            }
        } else {
            this.j = null;
        }
        this.k = authenticationExtensions;
        this.l = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0268  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0272  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0284  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x028e  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x02a0  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x02bd  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x02c7  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x02f4  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x02fe  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0310  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x031a  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x032c  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0336  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0342  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0218  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions a(org.json.JSONObject r33) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 904
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions.a(org.json.JSONObject):com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyCredentialCreationOptions)) {
            return false;
        }
        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = (PublicKeyCredentialCreationOptions) obj;
        if (!u.l(this.a, publicKeyCredentialCreationOptions.a) || !u.l(this.b, publicKeyCredentialCreationOptions.b) || !Arrays.equals(this.c, publicKeyCredentialCreationOptions.c) || !u.l(this.e, publicKeyCredentialCreationOptions.e)) {
            return false;
        }
        ArrayList arrayList = this.d;
        ArrayList arrayList2 = publicKeyCredentialCreationOptions.d;
        if (!arrayList.containsAll(arrayList2) || !arrayList2.containsAll(arrayList)) {
            return false;
        }
        ArrayList arrayList3 = this.f;
        ArrayList arrayList4 = publicKeyCredentialCreationOptions.f;
        return ((arrayList3 == null && arrayList4 == null) || (arrayList3 != null && arrayList4 != null && arrayList3.containsAll(arrayList4) && arrayList4.containsAll(arrayList3))) && u.l(this.g, publicKeyCredentialCreationOptions.g) && u.l(this.h, publicKeyCredentialCreationOptions.h) && u.l(this.i, publicKeyCredentialCreationOptions.i) && u.l(this.j, publicKeyCredentialCreationOptions.j) && u.l(this.k, publicKeyCredentialCreationOptions.k) && u.l(this.l, publicKeyCredentialCreationOptions.l);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, Integer.valueOf(Arrays.hashCode(this.c)), this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l});
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.a);
        String strValueOf2 = String.valueOf(this.b);
        String strG = com.google.android.gms.common.util.c.g(this.c);
        String strValueOf3 = String.valueOf(this.d);
        String strValueOf4 = String.valueOf(this.f);
        String strValueOf5 = String.valueOf(this.g);
        String strValueOf6 = String.valueOf(this.i);
        String strValueOf7 = String.valueOf(this.j);
        String strValueOf8 = String.valueOf(this.k);
        StringBuilder sbH = AbstractC0147y.h("PublicKeyCredentialCreationOptions{\n rp=", strValueOf, ", \n user=", strValueOf2, ", \n challenge=");
        B.u(sbH, strG, ", \n parameters=", strValueOf3, ", \n timeoutSeconds=");
        sbH.append(this.e);
        sbH.append(", \n excludeList=");
        sbH.append(strValueOf4);
        sbH.append(", \n authenticatorSelection=");
        sbH.append(strValueOf5);
        sbH.append(", \n requestId=");
        sbH.append(this.h);
        sbH.append(", \n tokenBinding=");
        sbH.append(strValueOf6);
        sbH.append(", \n attestationConveyancePreference=");
        return B.j(sbH, strValueOf7, ", \n authenticationExtensions=", strValueOf8, "}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        AbstractC3489l3.g(parcel, 3, this.b, i);
        AbstractC3489l3.d(parcel, 4, this.c);
        AbstractC3489l3.l(parcel, 5, this.d);
        Double d = this.e;
        if (d != null) {
            AbstractC3489l3.m(parcel, 6, 8);
            parcel.writeDouble(d.doubleValue());
        }
        AbstractC3489l3.l(parcel, 7, this.f);
        AbstractC3489l3.g(parcel, 8, this.g, i);
        Integer num = this.h;
        if (num != null) {
            AbstractC3489l3.m(parcel, 9, 4);
            parcel.writeInt(num.intValue());
        }
        AbstractC3489l3.g(parcel, 10, this.i, i);
        AttestationConveyancePreference attestationConveyancePreference = this.j;
        AbstractC3489l3.h(parcel, 11, attestationConveyancePreference == null ? null : attestationConveyancePreference.a);
        AbstractC3489l3.g(parcel, 12, this.k, i);
        AbstractC3489l3.h(parcel, 13, this.l);
        AbstractC3489l3.g(parcel, 14, this.m, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
