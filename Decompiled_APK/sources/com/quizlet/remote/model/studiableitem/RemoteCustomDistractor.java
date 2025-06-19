package com.quizlet.remote.model.studiableitem;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCustomDistractor {
    public final RemoteCustomTextDistractor a;

    public RemoteCustomDistractor(RemoteCustomTextDistractor remoteCustomTextDistractor) {
        this.a = remoteCustomTextDistractor;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteCustomDistractor) && Intrinsics.b(this.a, ((RemoteCustomDistractor) obj).a);
    }

    public final int hashCode() {
        RemoteCustomTextDistractor remoteCustomTextDistractor = this.a;
        if (remoteCustomTextDistractor == null) {
            return 0;
        }
        return remoteCustomTextDistractor.hashCode();
    }

    public final String toString() {
        return "RemoteCustomDistractor(text=" + this.a + ")";
    }
}
