package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4473d;
import com.quizlet.generated.enums.EnumC4479f;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4106a extends AbstractC4128g {
    public final String a;
    public final String b;
    public final EnumC4479f c;
    public final int d;
    public final EnumC4473d e;
    public final String f;
    public final String g;
    public final String h;
    public final Long i;

    public C4106a(String badgeId, String description, EnumC4479f goalType, int i, EnumC4473d goalCategory, String name, String imageUrl, String str, Long l) {
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
        this.h = str;
        this.i = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4106a)) {
            return false;
        }
        C4106a c4106a = (C4106a) obj;
        return Intrinsics.b(this.a, c4106a.a) && Intrinsics.b(this.b, c4106a.b) && this.c == c4106a.c && this.d == c4106a.d && this.e == c4106a.e && Intrinsics.b(this.f, c4106a.f) && Intrinsics.b(this.g, c4106a.g) && Intrinsics.b(this.h, c4106a.h) && Intrinsics.b(this.i, c4106a.i);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e((this.e.hashCode() + androidx.compose.animation.d0.b(this.d, (this.c.hashCode() + androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b)) * 31, 31)) * 31, 31, this.f), 31, this.g);
        String str = this.h;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.i;
        return iHashCode + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        String strT = android.support.v4.media.session.a.t(new StringBuilder("AchievementBadgeImageUrl(background="), this.g, ")");
        StringBuilder sb = new StringBuilder("AchievementBadge(badgeId=");
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
        androidx.compose.ui.node.B.u(sb, this.f, ", imageUrl=", strT, ", goalTextAlignment=");
        sb.append(this.h);
        sb.append(", winDate=");
        sb.append(this.i);
        sb.append(")");
        return sb.toString();
    }
}
