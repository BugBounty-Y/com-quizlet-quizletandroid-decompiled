package com.quizlet.quizletandroid.ui.joincontenttofolder.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;
    public final String b;
    public final int c;
    public final boolean d;

    public d(String profileImage, int i, String username, boolean z) {
        Intrinsics.checkNotNullParameter(profileImage, "profileImage");
        Intrinsics.checkNotNullParameter(username, "username");
        this.a = profileImage;
        this.b = username;
        this.c = i;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c && this.d == dVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.b(this.c, d0.e(this.a.hashCode() * 31, 31, this.b), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UserDisplayInfo(profileImage=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", badgeText=");
        sb.append(this.c);
        sb.append(", isVerified=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
