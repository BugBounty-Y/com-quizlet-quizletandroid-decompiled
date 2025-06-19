package com.quizlet.remote.model.achievements;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class BadgeDataResponse {
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final String e;
    public final String f;
    public final BadgeImageUrlResponse g;
    public final Long h;
    public final String i;

    public BadgeDataResponse(String badgeId, String description, String goalType, int i, String goalCategory, String name, BadgeImageUrlResponse imageUrl, Long l, String str) {
        Intrinsics.checkNotNullParameter(badgeId, "badgeId");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(goalType, "goalType");
        Intrinsics.checkNotNullParameter(goalCategory, "goalCategory");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = badgeId;
        this.b = description;
        this.c = goalType;
        this.d = i;
        this.e = goalCategory;
        this.f = name;
        this.g = imageUrl;
        this.h = l;
        this.i = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BadgeDataResponse)) {
            return false;
        }
        BadgeDataResponse badgeDataResponse = (BadgeDataResponse) obj;
        return Intrinsics.b(this.a, badgeDataResponse.a) && Intrinsics.b(this.b, badgeDataResponse.b) && Intrinsics.b(this.c, badgeDataResponse.c) && this.d == badgeDataResponse.d && Intrinsics.b(this.e, badgeDataResponse.e) && Intrinsics.b(this.f, badgeDataResponse.f) && Intrinsics.b(this.g, badgeDataResponse.g) && Intrinsics.b(this.h, badgeDataResponse.h) && Intrinsics.b(this.i, badgeDataResponse.i);
    }

    public final int hashCode() {
        int iHashCode = (this.g.hashCode() + d0.e(d0.e(d0.b(this.d, d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31), 31, this.e), 31, this.f)) * 31;
        Long l = this.h;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        String str = this.i;
        return iHashCode2 + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BadgeDataResponse(badgeId=");
        sb.append(this.a);
        sb.append(", description=");
        sb.append(this.b);
        sb.append(", goalType=");
        sb.append(this.c);
        sb.append(", goal=");
        sb.append(this.d);
        sb.append(", goalCategory=");
        sb.append(this.e);
        sb.append(", name=");
        sb.append(this.f);
        sb.append(", imageUrl=");
        sb.append(this.g);
        sb.append(", winDate=");
        sb.append(this.h);
        sb.append(", goalTextAlignment=");
        return android.support.v4.media.session.a.t(sb, this.i, ")");
    }
}
