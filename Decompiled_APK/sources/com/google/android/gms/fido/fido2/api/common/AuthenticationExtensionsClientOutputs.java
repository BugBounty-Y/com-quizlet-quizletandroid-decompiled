package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class AuthenticationExtensionsClientOutputs extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<AuthenticationExtensionsClientOutputs> CREATOR = new com.google.android.gms.common.i(24);
    public final UvmEntries a;
    public final zzf b;
    public final AuthenticationExtensionsCredPropsOutputs c;
    public final zzh d;
    public final String e;

    public AuthenticationExtensionsClientOutputs(UvmEntries uvmEntries, zzf zzfVar, AuthenticationExtensionsCredPropsOutputs authenticationExtensionsCredPropsOutputs, zzh zzhVar, String str) {
        this.a = uvmEntries;
        this.b = zzfVar;
        this.c = authenticationExtensionsCredPropsOutputs;
        this.d = zzhVar;
        this.e = str;
    }

    public final JSONObject a() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            AuthenticationExtensionsCredPropsOutputs authenticationExtensionsCredPropsOutputs = this.c;
            if (authenticationExtensionsCredPropsOutputs != null) {
                try {
                    JSONObject jSONObject2 = new JSONObject();
                    jSONObject2.put("rk", authenticationExtensionsCredPropsOutputs.a);
                    jSONObject.put("credProps", jSONObject2);
                } catch (JSONException e) {
                    throw new RuntimeException("Error encoding AuthenticationExtensionsCredPropsOutputs to JSON object", e);
                }
            }
            UvmEntries uvmEntries = this.a;
            if (uvmEntries != null) {
                jSONObject.put("uvm", uvmEntries.a());
            }
            zzh zzhVar = this.d;
            if (zzhVar != null) {
                jSONObject.put("prf", zzhVar.a());
            }
            String str = this.e;
            if (str != null) {
                jSONObject.put("txAuthSimple", str);
            }
            return jSONObject;
        } catch (JSONException e2) {
            throw new RuntimeException("Error encoding AuthenticationExtensionsClientOutputs to JSON object", e2);
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticationExtensionsClientOutputs)) {
            return false;
        }
        AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs = (AuthenticationExtensionsClientOutputs) obj;
        return u.l(this.a, authenticationExtensionsClientOutputs.a) && u.l(this.b, authenticationExtensionsClientOutputs.b) && u.l(this.c, authenticationExtensionsClientOutputs.c) && u.l(this.d, authenticationExtensionsClientOutputs.d) && u.l(this.e, authenticationExtensionsClientOutputs.e);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, this.d, this.e});
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("AuthenticationExtensionsClientOutputs{", a().toString(), "}");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 1, this.a, i);
        AbstractC3489l3.g(parcel, 2, this.b, i);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.g(parcel, 4, this.d, i);
        AbstractC3489l3.h(parcel, 5, this.e);
        AbstractC3489l3.o(iN, parcel);
    }
}
