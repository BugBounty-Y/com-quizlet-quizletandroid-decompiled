package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.facebook.internal.AbstractC1554i;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.C4957p;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AuthenticationTokenClaims implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<AuthenticationTokenClaims> CREATOR = new android.support.v4.media.a(11);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final long e;
    public final long f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;
    public final String m;
    public final Set n;
    public final String o;
    public final Map p;
    public final Map q;
    public final Map r;
    public final String s;
    public final String t;

    /* JADX WARN: Removed duplicated region for block: B:10:0x0067  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public AuthenticationTokenClaims(java.lang.String r11, java.lang.String r12) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 473
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.AuthenticationTokenClaims.<init>(java.lang.String, java.lang.String):void");
    }

    public final JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("jti", this.a);
        jSONObject.put("iss", this.b);
        jSONObject.put("aud", this.c);
        jSONObject.put("nonce", this.d);
        jSONObject.put("exp", this.e);
        jSONObject.put("iat", this.f);
        String str = this.g;
        if (str != null) {
            jSONObject.put("sub", str);
        }
        String str2 = this.h;
        if (str2 != null) {
            jSONObject.put("name", str2);
        }
        String str3 = this.i;
        if (str3 != null) {
            jSONObject.put("given_name", str3);
        }
        String str4 = this.j;
        if (str4 != null) {
            jSONObject.put("middle_name", str4);
        }
        String str5 = this.k;
        if (str5 != null) {
            jSONObject.put("family_name", str5);
        }
        String str6 = this.l;
        if (str6 != null) {
            jSONObject.put("email", str6);
        }
        String str7 = this.m;
        if (str7 != null) {
            jSONObject.put("picture", str7);
        }
        Set set = this.n;
        if (set != null) {
            jSONObject.put("user_friends", new JSONArray((Collection) set));
        }
        String str8 = this.o;
        if (str8 != null) {
            jSONObject.put("user_birthday", str8);
        }
        Map map = this.p;
        if (map != null) {
            jSONObject.put("user_age_range", new JSONObject(map));
        }
        Map map2 = this.q;
        if (map2 != null) {
            jSONObject.put("user_hometown", new JSONObject(map2));
        }
        Map map3 = this.r;
        if (map3 != null) {
            jSONObject.put("user_location", new JSONObject(map3));
        }
        String str9 = this.s;
        if (str9 != null) {
            jSONObject.put("user_gender", str9);
        }
        String str10 = this.t;
        if (str10 != null) {
            jSONObject.put("user_link", str10);
        }
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
        if (!(obj instanceof AuthenticationTokenClaims)) {
            return false;
        }
        AuthenticationTokenClaims authenticationTokenClaims = (AuthenticationTokenClaims) obj;
        return Intrinsics.b(this.a, authenticationTokenClaims.a) && Intrinsics.b(this.b, authenticationTokenClaims.b) && Intrinsics.b(this.c, authenticationTokenClaims.c) && Intrinsics.b(this.d, authenticationTokenClaims.d) && this.e == authenticationTokenClaims.e && this.f == authenticationTokenClaims.f && Intrinsics.b(this.g, authenticationTokenClaims.g) && Intrinsics.b(this.h, authenticationTokenClaims.h) && Intrinsics.b(this.i, authenticationTokenClaims.i) && Intrinsics.b(this.j, authenticationTokenClaims.j) && Intrinsics.b(this.k, authenticationTokenClaims.k) && Intrinsics.b(this.l, authenticationTokenClaims.l) && Intrinsics.b(this.m, authenticationTokenClaims.m) && Intrinsics.b(this.n, authenticationTokenClaims.n) && Intrinsics.b(this.o, authenticationTokenClaims.o) && Intrinsics.b(this.p, authenticationTokenClaims.p) && Intrinsics.b(this.q, authenticationTokenClaims.q) && Intrinsics.b(this.r, authenticationTokenClaims.r) && Intrinsics.b(this.s, authenticationTokenClaims.s) && Intrinsics.b(this.t, authenticationTokenClaims.t);
    }

    public final int hashCode() {
        int iE = d0.e(d0.d(d0.d(d0.e(d0.e(d0.e(d0.e(527, 31, this.a), 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g);
        String str = this.h;
        int iHashCode = (iE + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.i;
        int iHashCode2 = (iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.j;
        int iHashCode3 = (iHashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31;
        String str4 = this.k;
        int iHashCode4 = (iHashCode3 + (str4 != null ? str4.hashCode() : 0)) * 31;
        String str5 = this.l;
        int iHashCode5 = (iHashCode4 + (str5 != null ? str5.hashCode() : 0)) * 31;
        String str6 = this.m;
        int iHashCode6 = (iHashCode5 + (str6 != null ? str6.hashCode() : 0)) * 31;
        Set set = this.n;
        int iHashCode7 = (iHashCode6 + (set != null ? set.hashCode() : 0)) * 31;
        String str7 = this.o;
        int iHashCode8 = (iHashCode7 + (str7 != null ? str7.hashCode() : 0)) * 31;
        Map map = this.p;
        int iHashCode9 = (iHashCode8 + (map != null ? map.hashCode() : 0)) * 31;
        Map map2 = this.q;
        int iHashCode10 = (iHashCode9 + (map2 != null ? map2.hashCode() : 0)) * 31;
        Map map3 = this.r;
        int iHashCode11 = (iHashCode10 + (map3 != null ? map3.hashCode() : 0)) * 31;
        String str8 = this.s;
        int iHashCode12 = (iHashCode11 + (str8 != null ? str8.hashCode() : 0)) * 31;
        String str9 = this.t;
        return iHashCode12 + (str9 != null ? str9.hashCode() : 0);
    }

    public final String toString() {
        String string = a().toString();
        Intrinsics.checkNotNullExpressionValue(string, "claimsJsonObject.toString()");
        return string;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
        dest.writeString(this.d);
        dest.writeLong(this.e);
        dest.writeLong(this.f);
        dest.writeString(this.g);
        dest.writeString(this.h);
        dest.writeString(this.i);
        dest.writeString(this.j);
        dest.writeString(this.k);
        dest.writeString(this.l);
        dest.writeString(this.m);
        Set set = this.n;
        if (set == null) {
            dest.writeStringList(null);
        } else {
            dest.writeStringList(new ArrayList(set));
        }
        dest.writeString(this.o);
        dest.writeMap(this.p);
        dest.writeMap(this.q);
        dest.writeMap(this.r);
        dest.writeString(this.s);
        dest.writeString(this.t);
    }

    public AuthenticationTokenClaims(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        String string = parcel.readString();
        AbstractC1554i.j(string, "jti");
        this.a = string;
        String string2 = parcel.readString();
        AbstractC1554i.j(string2, "iss");
        this.b = string2;
        String string3 = parcel.readString();
        AbstractC1554i.j(string3, "aud");
        this.c = string3;
        String string4 = parcel.readString();
        AbstractC1554i.j(string4, "nonce");
        this.d = string4;
        this.e = parcel.readLong();
        this.f = parcel.readLong();
        String string5 = parcel.readString();
        AbstractC1554i.j(string5, "sub");
        this.g = string5;
        this.h = parcel.readString();
        this.i = parcel.readString();
        this.j = parcel.readString();
        this.k = parcel.readString();
        this.l = parcel.readString();
        this.m = parcel.readString();
        ArrayList<String> arrayListCreateStringArrayList = parcel.createStringArrayList();
        this.n = arrayListCreateStringArrayList != null ? Collections.unmodifiableSet(new HashSet(arrayListCreateStringArrayList)) : null;
        this.o = parcel.readString();
        HashMap hashMap = parcel.readHashMap(C4957p.a.getClass().getClassLoader());
        hashMap = hashMap == null ? null : hashMap;
        this.p = hashMap != null ? Collections.unmodifiableMap(hashMap) : null;
        HashMap hashMap2 = parcel.readHashMap(N.a.getClass().getClassLoader());
        hashMap2 = hashMap2 == null ? null : hashMap2;
        this.q = hashMap2 != null ? Collections.unmodifiableMap(hashMap2) : null;
        HashMap hashMap3 = parcel.readHashMap(N.class.getClassLoader());
        hashMap3 = hashMap3 == null ? null : hashMap3;
        this.r = hashMap3 != null ? Collections.unmodifiableMap(hashMap3) : null;
        this.s = parcel.readString();
        this.t = parcel.readString();
    }
}
