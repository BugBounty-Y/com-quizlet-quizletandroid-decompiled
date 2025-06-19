package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class School {
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

    public School(long j, String str, String str2, String str3, Integer num, Double d, Integer num2, Double d2, String name, String str4) {
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
        if (!(obj instanceof School)) {
            return false;
        }
        School school = (School) obj;
        return this.a == school.a && Intrinsics.b(this.b, school.b) && Intrinsics.b(this.c, school.c) && Intrinsics.b(this.d, school.d) && Intrinsics.b(this.e, school.e) && Intrinsics.b(this.f, school.f) && Intrinsics.b(this.g, school.g) && Intrinsics.b(this.h, school.h) && Intrinsics.b(this.i, school.i) && Intrinsics.b(this.j, school.j);
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
        int iE = androidx.compose.animation.d0.e((iHashCode7 + (d2 == null ? 0 : d2.hashCode())) * 31, 31, this.i);
        String str4 = this.j;
        return iE + (str4 != null ? str4.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("School(id=");
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

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ School(long j, String str, String str2, String str3, Integer num, Double d, Integer num2, Double d2, String str4, String str5, int i, DefaultConstructorMarker defaultConstructorMarker) {
        String str6;
        String str7;
        Double d3;
        num = (i & 16) != 0 ? null : num;
        d = (i & 32) != 0 ? null : d;
        num2 = (i & 64) != 0 ? null : num2;
        if ((i & 128) != 0) {
            str6 = str5;
            str7 = str4;
            d3 = null;
        } else {
            str6 = str5;
            str7 = str4;
            d3 = d2;
        }
        this(j, str, str2, str3, num, d, num2, d3, str7, str6);
    }
}
