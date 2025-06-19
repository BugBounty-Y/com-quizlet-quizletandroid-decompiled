package com.quizlet.quizletandroid.ui.profile.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;

    public i(String username, String imageProfileUrl, boolean z, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(imageProfileUrl, "imageProfileUrl");
        this.a = username;
        this.b = imageProfileUrl;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && Intrinsics.b(this.b, iVar.b) && this.c == iVar.c && this.d == iVar.d && this.e == iVar.e && this.f == iVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.g(d0.g(d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ViewState(username=");
        sb.append(this.a);
        sb.append(", imageProfileUrl=");
        sb.append(this.b);
        sb.append(", showReportOption=");
        sb.append(this.c);
        sb.append(", showToolbar=");
        sb.append(this.d);
        sb.append(", showHeaderButtons=");
        sb.append(this.e);
        sb.append(", showUpgradeButton=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
