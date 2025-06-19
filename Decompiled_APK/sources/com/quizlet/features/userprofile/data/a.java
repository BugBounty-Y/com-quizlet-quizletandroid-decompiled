package com.quizlet.features.userprofile.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;

    public a(String imageUrl, String userName, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(userName, "userName");
        this.a = imageUrl;
        this.b = userName;
        this.c = z;
        this.d = z2;
    }

    public static a a(a aVar, String imageUrl, int i) {
        if ((i & 1) != 0) {
            imageUrl = aVar.a;
        }
        String userName = aVar.b;
        boolean z = (i & 4) != 0 ? aVar.c : false;
        boolean z2 = aVar.d;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(userName, "userName");
        return new a(imageUrl, userName, z, z2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && this.d == aVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProfileUserData(imageUrl=");
        sb.append(this.a);
        sb.append(", userName=");
        sb.append(this.b);
        sb.append(", shouldShowUpgradeButton=");
        sb.append(this.c);
        sb.append(", hasFreeTrial=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
