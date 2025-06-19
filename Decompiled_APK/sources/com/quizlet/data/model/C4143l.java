package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4485h;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4143l extends AbstractC4152o {
    public final String a;
    public final EnumC4485h b;
    public final String c;
    public final int d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;

    public C4143l(String id, EnumC4485h type, String str, int i, String name, String description, String imageUrl, String theme, String str2) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(theme, "theme");
        this.a = id;
        this.b = type;
        this.c = str;
        this.d = i;
        this.e = name;
        this.f = description;
        this.g = imageUrl;
        this.h = theme;
        this.i = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4143l)) {
            return false;
        }
        C4143l c4143l = (C4143l) obj;
        return Intrinsics.b(this.a, c4143l.a) && this.b == c4143l.b && Intrinsics.b(this.c, c4143l.c) && this.d == c4143l.d && Intrinsics.b(this.e, c4143l.e) && Intrinsics.b(this.f, c4143l.f) && Intrinsics.b(this.g, c4143l.g) && Intrinsics.b(this.h, c4143l.h) && Intrinsics.b(this.i, c4143l.i);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        String str = this.c;
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.b(this.d, (iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
        String str2 = this.i;
        return iE + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AchievementNotification(id=");
        sb.append(this.a);
        sb.append(", type=");
        sb.append(this.b);
        sb.append(", winDate=");
        sb.append(this.c);
        sb.append(", goal=");
        sb.append(this.d);
        sb.append(", name=");
        sb.append(this.e);
        sb.append(", description=");
        sb.append(this.f);
        sb.append(", imageUrl=");
        sb.append(this.g);
        sb.append(", theme=");
        sb.append(this.h);
        sb.append(", goalTextAlignment=");
        return android.support.v4.media.session.a.t(sb, this.i, ")");
    }
}
