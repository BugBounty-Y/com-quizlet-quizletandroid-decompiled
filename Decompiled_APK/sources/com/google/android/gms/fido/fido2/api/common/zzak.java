package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import androidx.appcompat.widget.C0070a;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.fido.AbstractC2937a;
import com.google.android.gms.internal.fido.E;
import com.google.android.gms.internal.fido.F;
import com.google.android.gms.internal.fido.G;
import com.google.android.gms.internal.fido.H;
import com.google.android.gms.internal.fido.I;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class zzak extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzak> CREATOR = new com.google.android.gms.common.i(11);
    public static final byte[] b = "WebAuthn PRF\u0000".getBytes(StandardCharsets.UTF_8);
    public final byte[][] a;

    public zzak(byte[][] bArr) {
        u.b(bArr != null);
        u.b(1 == ((bArr.length & 1) ^ 1));
        int i = 0;
        while (i < bArr.length) {
            u.b(i == 0 || bArr[i] != null);
            int i2 = i + 1;
            u.b(bArr[i2] != null);
            int length = bArr[i2].length;
            u.b(length == 32 || length == 64);
            i += 2;
        }
        this.a = bArr;
    }

    public static zzak a(JSONObject jSONObject, boolean z) {
        ArrayList arrayList = new ArrayList();
        try {
            if (jSONObject.has("eval")) {
                arrayList.add(null);
                if (z) {
                    arrayList.add(g(jSONObject.getJSONObject("eval")));
                } else {
                    arrayList.add(h(jSONObject.getJSONObject("eval")));
                }
            }
            if (jSONObject.has("evalByCredential")) {
                JSONObject jSONObject2 = jSONObject.getJSONObject("evalByCredential");
                Iterator<String> itKeys = jSONObject2.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    arrayList.add(com.google.android.gms.common.util.c.f(next));
                    if (z) {
                        arrayList.add(g(jSONObject2.getJSONObject(next)));
                    } else {
                        arrayList.add(h(jSONObject2.getJSONObject(next)));
                    }
                }
            }
            return new zzak((byte[][]) arrayList.toArray(new byte[0][]));
        } catch (IllegalArgumentException unused) {
            throw new JSONException("invalid base64url value");
        }
    }

    public static JSONObject b(byte[] bArr) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (bArr.length == 32) {
            jSONObject.put("first", Base64.encodeToString(bArr, 11));
            return jSONObject;
        }
        jSONObject.put("first", Base64.encodeToString(bArr, 0, 32, 11));
        jSONObject.put("second", Base64.encodeToString(bArr, 32, 32, 11));
        return jSONObject;
    }

    public static byte[] c(byte[] bArr) {
        C0070a c0070a;
        E e;
        int i = H.a;
        I i2 = G.a;
        boolean z = i2.g;
        int i3 = i2.f;
        MessageDigest messageDigest = i2.e;
        if (z) {
            try {
                c0070a = new C0070a((MessageDigest) messageDigest.clone(), i3);
            } catch (CloneNotSupportedException unused) {
            }
        } else {
            try {
                c0070a = new C0070a(MessageDigest.getInstance(messageDigest.getAlgorithm()), i3);
            } catch (NoSuchAlgorithmException e2) {
                throw new AssertionError(e2);
            }
        }
        byte[] bArr2 = b;
        bArr2.getClass();
        int length = bArr2.length;
        if (c0070a.b) {
            throw new IllegalStateException("Cannot re-use a Hasher after calling hash() on it");
        }
        MessageDigest messageDigest2 = (MessageDigest) c0070a.c;
        messageDigest2.update(bArr2, 0, length);
        bArr.getClass();
        int length2 = bArr.length;
        if (c0070a.b) {
            throw new IllegalStateException("Cannot re-use a Hasher after calling hash() on it");
        }
        messageDigest2.update(bArr, 0, length2);
        if (c0070a.b) {
            throw new IllegalStateException("Cannot re-use a Hasher after calling hash() on it");
        }
        c0070a.b = true;
        int digestLength = messageDigest2.getDigestLength();
        int i4 = c0070a.a;
        if (i4 == digestLength) {
            byte[] bArrDigest = messageDigest2.digest();
            char[] cArr = F.a;
            e = new E(bArrDigest);
        } else {
            byte[] bArrCopyOf = Arrays.copyOf(messageDigest2.digest(), i4);
            char[] cArr2 = F.a;
            e = new E(bArrCopyOf);
        }
        return (byte[]) e.b.clone();
    }

    public static byte[] g(JSONObject jSONObject) throws JSONException {
        byte[] bArrF = com.google.android.gms.common.util.c.f(jSONObject.getString("first"));
        if (bArrF.length != 32) {
            throw new JSONException("hashed PRF value with wrong length");
        }
        if (!jSONObject.has("second")) {
            return bArrF;
        }
        byte[] bArrF2 = com.google.android.gms.common.util.c.f(jSONObject.getString("second"));
        if (bArrF2.length == 32) {
            return AbstractC2937a.k(bArrF, bArrF2);
        }
        throw new JSONException("hashed PRF value with wrong length");
    }

    public static byte[] h(JSONObject jSONObject) {
        byte[] bArrC = c(com.google.android.gms.common.util.c.f(jSONObject.getString("first")));
        return !jSONObject.has("second") ? bArrC : AbstractC2937a.k(bArrC, c(com.google.android.gms.common.util.c.f(jSONObject.getString("second"))));
    }

    public final boolean equals(Object obj) {
        if (obj instanceof zzak) {
            return Arrays.deepEquals(this.a, ((zzak) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = 0;
        for (byte[] bArr : this.a) {
            if (bArr != null) {
                iHashCode ^= Arrays.hashCode(new Object[]{bArr});
            }
        }
        return iHashCode;
    }

    public final String toString() throws JSONException {
        byte[][] bArr = this.a;
        try {
            JSONObject jSONObject = new JSONObject();
            JSONObject jSONObject2 = null;
            for (int i = 0; i < bArr.length; i += 2) {
                if (bArr[i] == null) {
                    jSONObject.put("eval", b(bArr[i + 1]));
                } else {
                    if (jSONObject2 == null) {
                        jSONObject2 = new JSONObject();
                        jSONObject.put("evalByCredential", jSONObject2);
                    }
                    jSONObject2.put(com.google.android.gms.common.util.c.g(bArr[i]), b(bArr[i + 1]));
                }
            }
            return "PrfExtension{" + jSONObject.toString() + "}";
        } catch (JSONException e) {
            return android.support.v4.media.session.a.B("PrfExtension{Exception:", e.getMessage(), "}");
        }
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        byte[][] bArr = this.a;
        if (bArr != null) {
            int iN2 = AbstractC3489l3.n(1, parcel);
            parcel.writeInt(bArr.length);
            for (byte[] bArr2 : bArr) {
                parcel.writeByteArray(bArr2);
            }
            AbstractC3489l3.o(iN2, parcel);
        }
        AbstractC3489l3.o(iN, parcel);
    }
}
