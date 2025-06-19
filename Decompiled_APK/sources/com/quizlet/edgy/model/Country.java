package com.quizlet.edgy.model;

import android.support.v4.media.session.a;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Country {
    public final String a;
    public final String b;

    public Country(String code, String name) {
        Intrinsics.checkNotNullParameter(code, "code");
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = code;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Country)) {
            return false;
        }
        Country country = (Country) obj;
        return Intrinsics.b(this.a, country.a) && Intrinsics.b(this.b, country.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Country(code=");
        sb.append(this.a);
        sb.append(", name=");
        return a.t(sb, this.b, ")");
    }
}
