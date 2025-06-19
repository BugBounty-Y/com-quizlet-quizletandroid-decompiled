package com.quizlet.remote.model.achievements;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class BadgeImageUrlResponse {
    public final String a;
    public final String b;

    public BadgeImageUrlResponse(String background, String backgroundPng) {
        Intrinsics.checkNotNullParameter(background, "background");
        Intrinsics.checkNotNullParameter(backgroundPng, "backgroundPng");
        this.a = background;
        this.b = backgroundPng;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BadgeImageUrlResponse)) {
            return false;
        }
        BadgeImageUrlResponse badgeImageUrlResponse = (BadgeImageUrlResponse) obj;
        return Intrinsics.b(this.a, badgeImageUrlResponse.a) && Intrinsics.b(this.b, badgeImageUrlResponse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BadgeImageUrlResponse(background=");
        sb.append(this.a);
        sb.append(", backgroundPng=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
