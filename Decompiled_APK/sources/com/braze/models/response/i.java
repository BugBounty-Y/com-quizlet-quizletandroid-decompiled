package com.braze.models.response;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i implements d {
    public final com.braze.requests.n a;
    public final int b;
    public final String c;

    public i(com.braze.requests.n originalRequest, int i, String str) {
        Intrinsics.checkNotNullParameter(originalRequest, "originalRequest");
        this.a = originalRequest;
        this.b = i;
        this.c = str;
    }

    @Override // com.braze.models.response.d
    public final String a() {
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && this.b == iVar.b && Intrinsics.b(this.c, iVar.c);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, this.a.hashCode() * 31, 31);
        String str = this.c;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{code = ");
        sb.append(this.b);
        sb.append(", reason = ");
        return d0.r(sb, this.c, '}');
    }
}
