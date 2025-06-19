package com.auth0.android.jwt;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.gson.internal.f;
import com.google.gson.k;
import com.google.gson.reflect.TypeToken;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class JWT implements Parcelable {
    public static final Parcelable.Creator<JWT> CREATOR = new android.support.v4.media.a(8);
    public final String a;
    public final d b;

    /* renamed from: com.auth0.android.jwt.JWT$2, reason: invalid class name */
    class AnonymousClass2 extends TypeToken<Map<String, String>> {
    }

    public JWT(String str) {
        String[] strArrSplit = str.split("\\.");
        if (strArrSplit.length == 2 && str.endsWith(".")) {
            strArrSplit = new String[]{strArrSplit[0], strArrSplit[1], ""};
        }
        if (strArrSplit.length != 3) {
            throw new DecodeException(AbstractC0147y.c(strArrSplit.length, "The token was expected to have 3 parts, but got ", "."));
        }
        try {
            try {
                this.b = (d) c().a(a(strArrSplit[1]), d.class);
                String str2 = strArrSplit[2];
                this.a = str;
            } catch (Exception e) {
                throw new DecodeException("The token's payload had an invalid JSON format.", e);
            }
        } catch (Exception e2) {
            throw new DecodeException("The token's payload had an invalid JSON format.", e2);
        }
    }

    public static String a(String str) {
        try {
            return new String(Base64.decode(str, 11), Charset.defaultCharset());
        } catch (IllegalArgumentException e) {
            throw new DecodeException("Received bytes didn't correspond to a valid Base64 encoded string.", e);
        }
    }

    public static k c() {
        f fVar = f.c;
        HashMap map = new HashMap();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        c cVar = new c();
        TypeToken typeToken = new TypeToken(d.class);
        arrayList.add(new com.google.gson.internal.bind.k(cVar, typeToken, typeToken.b == typeToken.a));
        ArrayList arrayList3 = new ArrayList(arrayList2.size() + arrayList.size() + 3);
        arrayList3.addAll(arrayList);
        Collections.reverse(arrayList3);
        ArrayList arrayList4 = new ArrayList(arrayList2);
        Collections.reverse(arrayList4);
        arrayList3.addAll(arrayList4);
        boolean z = com.google.gson.internal.sql.b.a;
        return new k(fVar, map, arrayList3);
    }

    public final a b(String str) {
        a aVar = (a) this.b.a.get(str);
        return aVar != null ? aVar : new a();
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final String toString() {
        return this.a;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.a);
    }
}
