package com.quizlet.data.model;

import java.time.LocalDate;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4114c {
    public final String a;
    public final int b;
    public final boolean c;
    public final String d;
    public final String e;
    public final String f;
    public final EnumC4110b g;
    public final LocalDate h;

    public C4114c(String badgeId, int i, boolean z, String title, String description, String imageUrl, EnumC4110b enumC4110b, LocalDate localDate) {
        Intrinsics.checkNotNullParameter(badgeId, "badgeId");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = badgeId;
        this.b = i;
        this.c = z;
        this.d = title;
        this.e = description;
        this.f = imageUrl;
        this.g = enumC4110b;
        this.h = localDate;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4114c)) {
            return false;
        }
        C4114c c4114c = (C4114c) obj;
        return Intrinsics.b(this.a, c4114c.a) && this.b == c4114c.b && this.c == c4114c.c && Intrinsics.b(this.d, c4114c.d) && Intrinsics.b(this.e, c4114c.e) && Intrinsics.b(this.f, c4114c.f) && this.g == c4114c.g && Intrinsics.b(this.h, c4114c.h);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c), 31, this.d), 31, this.e), 31, this.f);
        EnumC4110b enumC4110b = this.g;
        int iHashCode = (iE + (enumC4110b == null ? 0 : enumC4110b.hashCode())) * 31;
        LocalDate localDate = this.h;
        return iHashCode + (localDate != null ? localDate.hashCode() : 0);
    }

    public final String toString() {
        return "AchievementBadgeData(badgeId=" + this.a + ", count=" + this.b + ", earned=" + this.c + ", title=" + this.d + ", description=" + this.e + ", imageUrl=" + this.f + ", goalTextAlignment=" + this.g + ", earnedDate=" + this.h + ")";
    }
}
