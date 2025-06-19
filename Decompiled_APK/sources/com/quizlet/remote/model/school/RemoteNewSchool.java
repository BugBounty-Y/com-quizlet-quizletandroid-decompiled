package com.quizlet.remote.model.school;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNewSchool {
    public final String a;
    public final String b;
    public final String c;
    public final String d;

    public RemoteNewSchool(String name, String city, String state, String countryCode) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(city, "city");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(countryCode, "countryCode");
        this.a = name;
        this.b = city;
        this.c = state;
        this.d = countryCode;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteNewSchool)) {
            return false;
        }
        RemoteNewSchool remoteNewSchool = (RemoteNewSchool) obj;
        return Intrinsics.b(this.a, remoteNewSchool.a) && Intrinsics.b(this.b, remoteNewSchool.b) && Intrinsics.b(this.c, remoteNewSchool.c) && Intrinsics.b(this.d, remoteNewSchool.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteNewSchool(name=");
        sb.append(this.a);
        sb.append(", city=");
        sb.append(this.b);
        sb.append(", state=");
        sb.append(this.c);
        sb.append(", countryCode=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
