package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import androidx.compose.animation.d0;
import com.facebook.internal.AbstractC1554i;
import java.nio.charset.Charset;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AuthenticationTokenHeader implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<AuthenticationTokenHeader> CREATOR = new android.support.v4.media.a(12);
    public final String a;
    public final String b;
    public final String c;

    public AuthenticationTokenHeader(String encodedHeaderString) throws JSONException {
        Intrinsics.checkNotNullParameter(encodedHeaderString, "encodedHeaderString");
        AbstractC1554i.h(encodedHeaderString, "encodedHeaderString");
        byte[] decodedBytes = Base64.decode(encodedHeaderString, 0);
        Intrinsics.checkNotNullExpressionValue(decodedBytes, "decodedBytes");
        Charset charset = Charsets.UTF_8;
        try {
            JSONObject jSONObject = new JSONObject(new String(decodedBytes, charset));
            String alg = jSONObject.optString("alg");
            Intrinsics.checkNotNullExpressionValue(alg, "alg");
            boolean z = alg.length() > 0 && alg.equals("RS256");
            String strOptString = jSONObject.optString("kid");
            Intrinsics.checkNotNullExpressionValue(strOptString, "jsonObj.optString(\"kid\")");
            boolean z2 = strOptString.length() > 0;
            String strOptString2 = jSONObject.optString("typ");
            Intrinsics.checkNotNullExpressionValue(strOptString2, "jsonObj.optString(\"typ\")");
            boolean z3 = strOptString2.length() > 0;
            if (z && z2 && z3) {
                byte[] decodedBytes2 = Base64.decode(encodedHeaderString, 0);
                Intrinsics.checkNotNullExpressionValue(decodedBytes2, "decodedBytes");
                JSONObject jSONObject2 = new JSONObject(new String(decodedBytes2, charset));
                String string = jSONObject2.getString("alg");
                Intrinsics.checkNotNullExpressionValue(string, "jsonObj.getString(\"alg\")");
                this.a = string;
                String string2 = jSONObject2.getString("typ");
                Intrinsics.checkNotNullExpressionValue(string2, "jsonObj.getString(\"typ\")");
                this.b = string2;
                String string3 = jSONObject2.getString("kid");
                Intrinsics.checkNotNullExpressionValue(string3, "jsonObj.getString(\"kid\")");
                this.c = string3;
                return;
            }
        } catch (JSONException unused) {
        }
        throw new IllegalArgumentException("Invalid Header");
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AuthenticationTokenHeader)) {
            return false;
        }
        AuthenticationTokenHeader authenticationTokenHeader = (AuthenticationTokenHeader) obj;
        return Intrinsics.b(this.a, authenticationTokenHeader.a) && Intrinsics.b(this.b, authenticationTokenHeader.b) && Intrinsics.b(this.c, authenticationTokenHeader.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(d0.e(527, 31, this.a), 31, this.b);
    }

    public final String toString() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("alg", this.a);
        jSONObject.put("typ", this.b);
        jSONObject.put("kid", this.c);
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "headerJsonObject.toString()");
        return string;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
    }

    public AuthenticationTokenHeader(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        String string = parcel.readString();
        AbstractC1554i.j(string, "alg");
        this.a = string;
        String string2 = parcel.readString();
        AbstractC1554i.j(string2, "typ");
        this.b = string2;
        String string3 = parcel.readString();
        AbstractC1554i.j(string3, "kid");
        this.c = string3;
    }
}
