package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D {
    public final String a;
    public final int b;
    public final int c;
    public final boolean d;

    public D(int i, int i2, String processName, boolean z) {
        Intrinsics.checkNotNullParameter(processName, "processName");
        this.a = processName;
        this.b = i;
        this.c = i2;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return Intrinsics.b(this.a, d.a) && this.b == d.b && this.c == d.c && this.d == d.d;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int hashCode() {
        int iB = androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31);
        boolean z = this.d;
        int i = z;
        if (z != 0) {
            i = 1;
        }
        return iB + i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProcessDetails(processName=");
        sb.append(this.a);
        sb.append(", pid=");
        sb.append(this.b);
        sb.append(", importance=");
        sb.append(this.c);
        sb.append(", isDefaultProcess=");
        return android.support.v4.media.session.a.u(sb, this.d, ')');
    }
}
