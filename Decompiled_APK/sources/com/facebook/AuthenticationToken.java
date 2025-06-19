package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.facebook.internal.AbstractC1554i;
import com.google.android.gms.internal.mlkit_vision_common.H2;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AuthenticationToken implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<AuthenticationToken> CREATOR = new android.support.v4.media.a(10);
    public final String a;
    public final String b;
    public final AuthenticationTokenHeader c;
    public final AuthenticationTokenClaims d;
    public final String e;

    public AuthenticationToken(String token, String expectedNonce) {
        Intrinsics.checkNotNullParameter(token, "token");
        Intrinsics.checkNotNullParameter(expectedNonce, "expectedNonce");
        AbstractC1554i.h(token, "token");
        AbstractC1554i.h(expectedNonce, "expectedNonce");
        boolean zH = false;
        List listSplit$default = StringsKt__StringsKt.split$default(token, new String[]{"."}, false, 0, 6, null);
        if (listSplit$default.size() != 3) {
            throw new IllegalArgumentException("Invalid IdToken string");
        }
        String str = (String) listSplit$default.get(0);
        String str2 = (String) listSplit$default.get(1);
        String str3 = (String) listSplit$default.get(2);
        this.a = token;
        this.b = expectedNonce;
        AuthenticationTokenHeader authenticationTokenHeader = new AuthenticationTokenHeader(str);
        this.c = authenticationTokenHeader;
        this.d = new AuthenticationTokenClaims(str2, expectedNonce);
        try {
            String strG = H2.g(authenticationTokenHeader.c);
            if (strG != null) {
                zH = H2.h(H2.f(strG), str + '.' + str2, str3);
            }
        } catch (IOException | InvalidKeySpecException unused) {
        }
        if (!zH) {
            throw new IllegalArgumentException("Invalid Signature");
        }
        this.e = str3;
    }

    public final JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("token_string", this.a);
        jSONObject.put("expected_nonce", this.b);
        AuthenticationTokenHeader authenticationTokenHeader = this.c;
        authenticationTokenHeader.getClass();
        JSONObject jSONObject2 = new JSONObject();
        jSONObject2.put("alg", authenticationTokenHeader.a);
        jSONObject2.put("typ", authenticationTokenHeader.b);
        jSONObject2.put("kid", authenticationTokenHeader.c);
        jSONObject.put("header", jSONObject2);
        jSONObject.put("claims", this.d.a());
        jSONObject.put("signature", this.e);
        return jSONObject;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AuthenticationToken)) {
            return false;
        }
        AuthenticationToken authenticationToken = (AuthenticationToken) obj;
        return Intrinsics.b(this.a, authenticationToken.a) && Intrinsics.b(this.b, authenticationToken.b) && Intrinsics.b(this.c, authenticationToken.c) && Intrinsics.b(this.d, authenticationToken.d) && Intrinsics.b(this.e, authenticationToken.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.e(d0.e(527, 31, this.a), 31, this.b)) * 31)) * 31);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeParcelable(this.c, i);
        dest.writeParcelable(this.d, i);
        dest.writeString(this.e);
    }

    public AuthenticationToken(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        String string = parcel.readString();
        AbstractC1554i.j(string, "token");
        this.a = string;
        String string2 = parcel.readString();
        AbstractC1554i.j(string2, "expectedNonce");
        this.b = string2;
        Parcelable parcelable = parcel.readParcelable(AuthenticationTokenHeader.class.getClassLoader());
        if (parcelable != null) {
            this.c = (AuthenticationTokenHeader) parcelable;
            Parcelable parcelable2 = parcel.readParcelable(AuthenticationTokenClaims.class.getClassLoader());
            if (parcelable2 != null) {
                this.d = (AuthenticationTokenClaims) parcelable2;
                String string3 = parcel.readString();
                AbstractC1554i.j(string3, "signature");
                this.e = string3;
                return;
            }
            throw new IllegalStateException("Required value was null.");
        }
        throw new IllegalStateException("Required value was null.");
    }
}
