package com.quizlet.features.userprofile.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends k {
    public final a a;
    public final androidx.camera.core.impl.utils.e b;
    public final int c;

    public j(a userData, androidx.camera.core.impl.utils.e eVar, int i) {
        Intrinsics.checkNotNullParameter(userData, "userData");
        this.a = userData;
        this.b = eVar;
        this.c = i;
    }

    public static j a(j jVar, a userData) {
        Intrinsics.checkNotNullParameter(userData, "userData");
        return new j(userData, jVar.b, jVar.c);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b) && this.c == jVar.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        androidx.camera.core.impl.utils.e eVar = this.b;
        return Integer.hashCode(this.c) + ((iHashCode + (eVar == null ? 0 : eVar.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MainState(userData=");
        sb.append(this.a);
        sb.append(", achievementsStreakData=");
        sb.append(this.b);
        sb.append(", unreadActivityCount=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
