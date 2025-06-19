package com.quizlet.quizletandroid.ui.group.classcontent.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final int e;
    public final int f;
    public final int g;

    public b(long j, String username, String imageUrl, boolean z, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = j;
        this.b = username;
        this.c = imageUrl;
        this.d = z;
        this.e = i;
        this.f = i2;
        this.g = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && this.d == bVar.d && this.e == bVar.e && this.f == bVar.f && this.g == bVar.g;
    }

    public final int hashCode() {
        return Integer.hashCode(this.g) + d0.b(this.f, d0.b(this.e, d0.g(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassContentUser(id=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", imageUrl=");
        sb.append(this.c);
        sb.append(", isVerified=");
        sb.append(this.d);
        sb.append(", badgeText=");
        sb.append(this.e);
        sb.append(", userUpgradeType=");
        sb.append(this.f);
        sb.append(", selfIdentifiedTeacherStatus=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}
