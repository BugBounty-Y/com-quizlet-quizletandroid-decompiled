package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4479f;
import java.time.LocalDateTime;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.d2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4121d2 extends h2 {
    public final EnumC4479f a;
    public final int b;
    public final boolean c;
    public final LocalDateTime d;
    public final LocalDateTime e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;

    public C4121d2(EnumC4479f type, int i, boolean z, LocalDateTime startDate, LocalDateTime expirationDate, String name, String description, String imageUrl, String str) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(startDate, "startDate");
        Intrinsics.checkNotNullParameter(expirationDate, "expirationDate");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = type;
        this.b = i;
        this.c = z;
        this.d = startDate;
        this.e = expirationDate;
        this.f = name;
        this.g = description;
        this.h = imageUrl;
        this.i = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4121d2)) {
            return false;
        }
        C4121d2 c4121d2 = (C4121d2) obj;
        return this.a == c4121d2.a && this.b == c4121d2.b && this.c == c4121d2.c && Intrinsics.b(this.d, c4121d2.d) && Intrinsics.b(this.e, c4121d2.e) && Intrinsics.b(this.f, c4121d2.f) && Intrinsics.b(this.g, c4121d2.g) && Intrinsics.b(this.h, c4121d2.h) && Intrinsics.b(this.i, c4121d2.i);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e((this.e.hashCode() + ((this.d.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c)) * 31)) * 31, 31, this.f), 31, this.g), 31, this.h);
        String str = this.i;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyStreak(type=");
        sb.append(this.a);
        sb.append(", count=");
        sb.append(this.b);
        sb.append(", hasShownModal=");
        sb.append(this.c);
        sb.append(", startDate=");
        sb.append(this.d);
        sb.append(", expirationDate=");
        sb.append(this.e);
        sb.append(", name=");
        sb.append(this.f);
        sb.append(", description=");
        sb.append(this.g);
        sb.append(", imageUrl=");
        sb.append(this.h);
        sb.append(", goalTextAlignment=");
        return android.support.v4.media.session.a.t(sb, this.i, ")");
    }
}
