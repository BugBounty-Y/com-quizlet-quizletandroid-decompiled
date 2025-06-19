package com.facebook;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.facebook.internal.AbstractC1554i;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class Profile implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<Profile> CREATOR = new android.support.v4.media.a(15);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final Uri f;
    public final Uri g;

    public Profile(String str, String str2, String str3, String str4, String str5, Uri uri, Uri uri2) {
        AbstractC1554i.j(str, "id");
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
        this.f = uri;
        this.g = uri2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        String str;
        String str2;
        String str3;
        String str4;
        Uri uri;
        Uri uri2;
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Profile)) {
            return false;
        }
        String str5 = this.a;
        return ((str5 == null && ((Profile) obj).a == null) || Intrinsics.b(str5, ((Profile) obj).a)) && (((str = this.b) == null && ((Profile) obj).b == null) || Intrinsics.b(str, ((Profile) obj).b)) && ((((str2 = this.c) == null && ((Profile) obj).c == null) || Intrinsics.b(str2, ((Profile) obj).c)) && ((((str3 = this.d) == null && ((Profile) obj).d == null) || Intrinsics.b(str3, ((Profile) obj).d)) && ((((str4 = this.e) == null && ((Profile) obj).e == null) || Intrinsics.b(str4, ((Profile) obj).e)) && ((((uri = this.f) == null && ((Profile) obj).f == null) || Intrinsics.b(uri, ((Profile) obj).f)) && (((uri2 = this.g) == null && ((Profile) obj).g == null) || Intrinsics.b(uri2, ((Profile) obj).g))))));
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = 527 + (str != null ? str.hashCode() : 0);
        String str2 = this.b;
        if (str2 != null) {
            iHashCode = (iHashCode * 31) + str2.hashCode();
        }
        String str3 = this.c;
        if (str3 != null) {
            iHashCode = (iHashCode * 31) + str3.hashCode();
        }
        String str4 = this.d;
        if (str4 != null) {
            iHashCode = (iHashCode * 31) + str4.hashCode();
        }
        String str5 = this.e;
        if (str5 != null) {
            iHashCode = (iHashCode * 31) + str5.hashCode();
        }
        Uri uri = this.f;
        if (uri != null) {
            iHashCode = (iHashCode * 31) + uri.hashCode();
        }
        Uri uri2 = this.g;
        if (uri2 != null) {
            return uri2.hashCode() + (iHashCode * 31);
        }
        return iHashCode;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
        dest.writeString(this.d);
        dest.writeString(this.e);
        Uri uri = this.f;
        dest.writeString(uri != null ? uri.toString() : null);
        Uri uri2 = this.g;
        dest.writeString(uri2 != null ? uri2.toString() : null);
    }

    public Profile(JSONObject jsonObject) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        this.a = jsonObject.optString("id", null);
        this.b = jsonObject.optString("first_name", null);
        this.c = jsonObject.optString("middle_name", null);
        this.d = jsonObject.optString("last_name", null);
        this.e = jsonObject.optString("name", null);
        String strOptString = jsonObject.optString("link_uri", null);
        this.f = strOptString == null ? null : Uri.parse(strOptString);
        String strOptString2 = jsonObject.optString("picture_uri", null);
        this.g = strOptString2 != null ? Uri.parse(strOptString2) : null;
    }

    public Profile(Parcel parcel) {
        this.a = parcel.readString();
        this.b = parcel.readString();
        this.c = parcel.readString();
        this.d = parcel.readString();
        this.e = parcel.readString();
        String string = parcel.readString();
        this.f = string == null ? null : Uri.parse(string);
        String string2 = parcel.readString();
        this.g = string2 != null ? Uri.parse(string2) : null;
    }
}
