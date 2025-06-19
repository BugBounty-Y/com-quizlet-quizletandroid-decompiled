package com.quizlet.remote.model.course;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNewCourse {
    public final String a;
    public final String b;

    public RemoteNewCourse(String name, String code) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(code, "code");
        this.a = name;
        this.b = code;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteNewCourse)) {
            return false;
        }
        RemoteNewCourse remoteNewCourse = (RemoteNewCourse) obj;
        return Intrinsics.b(this.a, remoteNewCourse.a) && Intrinsics.b(this.b, remoteNewCourse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteNewCourse(name=");
        sb.append(this.a);
        sb.append(", code=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
