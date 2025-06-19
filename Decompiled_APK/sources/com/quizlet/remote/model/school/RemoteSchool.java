package com.quizlet.remote.model.school;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSchool {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final Integer e;
    public final Double f;
    public final Integer g;
    public final Double h;
    public final String i;
    public final String j;

    public RemoteSchool(long j, String str, String str2, String str3, Integer num, Double d, Integer num2, Double d2, String name, String str4) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = num;
        this.f = d;
        this.g = num2;
        this.h = d2;
        this.i = name;
        this.j = str4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSchool)) {
            return false;
        }
        RemoteSchool remoteSchool = (RemoteSchool) obj;
        return this.a == remoteSchool.a && Intrinsics.b(this.b, remoteSchool.b) && Intrinsics.b(this.c, remoteSchool.c) && Intrinsics.b(this.d, remoteSchool.d) && Intrinsics.b(this.e, remoteSchool.e) && Intrinsics.b(this.f, remoteSchool.f) && Intrinsics.b(this.g, remoteSchool.g) && Intrinsics.b(this.h, remoteSchool.h) && Intrinsics.b(this.i, remoteSchool.i) && Intrinsics.b(this.j, remoteSchool.j);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Integer num = this.e;
        int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
        Double d = this.f;
        int iHashCode6 = (iHashCode5 + (d == null ? 0 : d.hashCode())) * 31;
        Integer num2 = this.g;
        int iHashCode7 = (iHashCode6 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Double d2 = this.h;
        int iE = d0.e((iHashCode7 + (d2 == null ? 0 : d2.hashCode())) * 31, 31, this.i);
        String str4 = this.j;
        return iE + (str4 != null ? str4.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSchool(id=");
        sb.append(this.a);
        sb.append(", city=");
        sb.append(this.b);
        sb.append(", country=");
        sb.append(this.c);
        sb.append(", countryCode=");
        sb.append(this.d);
        sb.append(", lastModified=");
        sb.append(this.e);
        sb.append(", latitude=");
        sb.append(this.f);
        sb.append(", level=");
        sb.append(this.g);
        sb.append(", longitude=");
        sb.append(this.h);
        sb.append(", name=");
        sb.append(this.i);
        sb.append(", state=");
        return android.support.v4.media.session.a.t(sb, this.j, ")");
    }
}
