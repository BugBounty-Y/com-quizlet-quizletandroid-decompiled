package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import androidx.compose.animation.d0;
import com.facebook.internal.AbstractC1554i;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AccessToken implements Parcelable {
    public final Date a;
    public final Set b;
    public final Set c;
    public final Set d;
    public final String e;
    public final g f;
    public final Date g;
    public final String h;
    public final String i;
    public final Date j;
    public final String k;
    public static final Date l = new Date(Long.MAX_VALUE);
    public static final Date m = new Date();
    public static final g n = g.FACEBOOK_APPLICATION_WEB;

    @NotNull
    public static final Parcelable.Creator<AccessToken> CREATOR = new android.support.v4.media.a(9);

    public /* synthetic */ AccessToken(String str, String str2, String str3, Collection collection, Collection collection2, Collection collection3, g gVar, Date date, Date date2, Date date3) {
        this(str, str2, str3, collection, collection2, collection3, gVar, date, date2, date3, "facebook");
    }

    public final JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("version", 1);
        jSONObject.put("token", this.e);
        jSONObject.put("expires_at", this.a.getTime());
        jSONObject.put("permissions", new JSONArray((Collection) this.b));
        jSONObject.put("declined_permissions", new JSONArray((Collection) this.c));
        jSONObject.put("expired_permissions", new JSONArray((Collection) this.d));
        jSONObject.put("last_refresh", this.g.getTime());
        jSONObject.put("source", this.f.name());
        jSONObject.put("application_id", this.h);
        jSONObject.put("user_id", this.i);
        jSONObject.put("data_access_expiration_time", this.j.getTime());
        String str = this.k;
        if (str != null) {
            jSONObject.put("graph_domain", str);
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
        if (!(obj instanceof AccessToken)) {
            return false;
        }
        AccessToken accessToken = (AccessToken) obj;
        if (Intrinsics.b(this.a, accessToken.a) && Intrinsics.b(this.b, accessToken.b) && Intrinsics.b(this.c, accessToken.c) && Intrinsics.b(this.d, accessToken.d) && Intrinsics.b(this.e, accessToken.e) && this.f == accessToken.f && Intrinsics.b(this.g, accessToken.g) && Intrinsics.b(this.h, accessToken.h) && Intrinsics.b(this.i, accessToken.i) && Intrinsics.b(this.j, accessToken.j)) {
            String str = this.k;
            String str2 = accessToken.k;
            if (str == null ? str2 == null : Intrinsics.b(str, str2)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (this.j.hashCode() + d0.e(d0.e((this.g.hashCode() + ((this.f.hashCode() + d0.e((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + ((this.a.hashCode() + 527) * 31)) * 31)) * 31)) * 31, 31, this.e)) * 31)) * 31, 31, this.h), 31, this.i)) * 31;
        String str = this.k;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{AccessToken token:ACCESS_TOKEN_REMOVED permissions:[");
        o.h(y.b);
        sb.append(TextUtils.join(", ", this.b));
        sb.append("]}");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "builder.toString()");
        return string;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a.getTime());
        dest.writeStringList(new ArrayList(this.b));
        dest.writeStringList(new ArrayList(this.c));
        dest.writeStringList(new ArrayList(this.d));
        dest.writeString(this.e);
        dest.writeString(this.f.name());
        dest.writeLong(this.g.getTime());
        dest.writeString(this.h);
        dest.writeString(this.i);
        dest.writeLong(this.j.getTime());
        dest.writeString(this.k);
    }

    public AccessToken(String accessToken, String applicationId, String userId, Collection collection, Collection collection2, Collection collection3, g gVar, Date date, Date date2, Date date3, String str) {
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        Intrinsics.checkNotNullParameter(userId, "userId");
        AbstractC1554i.h(accessToken, "accessToken");
        AbstractC1554i.h(applicationId, "applicationId");
        AbstractC1554i.h(userId, "userId");
        Date date4 = l;
        this.a = date == null ? date4 : date;
        Set setUnmodifiableSet = Collections.unmodifiableSet(collection != null ? new HashSet(collection) : new HashSet());
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(if (perm…missions) else HashSet())");
        this.b = setUnmodifiableSet;
        Set setUnmodifiableSet2 = Collections.unmodifiableSet(collection2 != null ? new HashSet(collection2) : new HashSet());
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet2, "unmodifiableSet(\n       …missions) else HashSet())");
        this.c = setUnmodifiableSet2;
        Set setUnmodifiableSet3 = Collections.unmodifiableSet(collection3 != null ? new HashSet(collection3) : new HashSet());
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet3, "unmodifiableSet(\n       …missions) else HashSet())");
        this.d = setUnmodifiableSet3;
        this.e = accessToken;
        gVar = gVar == null ? n : gVar;
        if (str != null && str.equals("instagram")) {
            int iOrdinal = gVar.ordinal();
            if (iOrdinal == 1) {
                gVar = g.INSTAGRAM_APPLICATION_WEB;
            } else if (iOrdinal == 4) {
                gVar = g.INSTAGRAM_WEB_VIEW;
            } else if (iOrdinal == 5) {
                gVar = g.INSTAGRAM_CUSTOM_CHROME_TAB;
            }
        }
        this.f = gVar;
        this.g = date2 == null ? m : date2;
        this.h = applicationId;
        this.i = userId;
        this.j = (date3 == null || date3.getTime() == 0) ? date4 : date3;
        this.k = str == null ? "facebook" : str;
    }

    public AccessToken(Parcel parcel) {
        g gVarValueOf;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        this.a = new Date(parcel.readLong());
        ArrayList arrayList = new ArrayList();
        parcel.readStringList(arrayList);
        Set setUnmodifiableSet = Collections.unmodifiableSet(new HashSet(arrayList));
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(HashSet(permissionsList))");
        this.b = setUnmodifiableSet;
        arrayList.clear();
        parcel.readStringList(arrayList);
        Set setUnmodifiableSet2 = Collections.unmodifiableSet(new HashSet(arrayList));
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet2, "unmodifiableSet(HashSet(permissionsList))");
        this.c = setUnmodifiableSet2;
        arrayList.clear();
        parcel.readStringList(arrayList);
        Set setUnmodifiableSet3 = Collections.unmodifiableSet(new HashSet(arrayList));
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet3, "unmodifiableSet(HashSet(permissionsList))");
        this.d = setUnmodifiableSet3;
        String string = parcel.readString();
        AbstractC1554i.j(string, "token");
        this.e = string;
        String string2 = parcel.readString();
        if (string2 != null) {
            gVarValueOf = g.valueOf(string2);
        } else {
            gVarValueOf = n;
        }
        this.f = gVarValueOf;
        this.g = new Date(parcel.readLong());
        String string3 = parcel.readString();
        AbstractC1554i.j(string3, "applicationId");
        this.h = string3;
        String string4 = parcel.readString();
        AbstractC1554i.j(string4, "userId");
        this.i = string4;
        this.j = new Date(parcel.readLong());
        this.k = parcel.readString();
    }
}
