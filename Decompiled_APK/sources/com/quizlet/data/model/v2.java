package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class v2 {
    public static final v2 d = new v2(0, "", "");
    public final String a;
    public final String b;
    public final int c;

    public v2(int i, String userName, String userImage) {
        Intrinsics.checkNotNullParameter(userName, "userName");
        Intrinsics.checkNotNullParameter(userImage, "userImage");
        this.a = userName;
        this.b = userImage;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v2)) {
            return false;
        }
        v2 v2Var = (v2) obj;
        return Intrinsics.b(this.a, v2Var.a) && Intrinsics.b(this.b, v2Var.b) && this.c == v2Var.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UserProfileAvatarData(userName=");
        sb.append(this.a);
        sb.append(", userImage=");
        sb.append(this.b);
        sb.append(", unreadNotificationsCount=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
