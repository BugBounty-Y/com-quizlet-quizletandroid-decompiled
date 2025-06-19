package com.quizlet.data.connectivity;

import androidx.compose.animation.d0;

/* loaded from: classes2.dex */
public final class b {
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public b(boolean z, boolean z2, boolean z3) {
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b && this.c == bVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NetworkStatusChangeEvent(isConnected=");
        sb.append(this.a);
        sb.append(", isWifi=");
        sb.append(this.b);
        sb.append(", wasPreviouslyConnected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
