package com.braze.models.response;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements d {
    public final com.braze.requests.n a;
    public final int b;
    public final String c;
    public final String d;

    public h(com.braze.requests.n originalRequest, int i, String str, String str2) {
        Intrinsics.checkNotNullParameter(originalRequest, "originalRequest");
        this.a = originalRequest;
        this.b = i;
        this.c = str;
        this.d = str2;
    }

    @Override // com.braze.models.response.d
    public final String a() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b && Intrinsics.b(this.c, hVar.c) && Intrinsics.b(this.d, hVar.d);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, this.a.hashCode() * 31, 31);
        String str = this.c;
        int iHashCode = (iB + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{code = ");
        sb.append(this.b);
        sb.append(", reason = ");
        sb.append(this.c);
        sb.append(", message = ");
        return d0.r(sb, this.d, '}');
    }
}
