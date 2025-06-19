package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class W extends B0 {
    public final String a;
    public final int b;
    public final List c;

    public W(String str, List list, int i) {
        this.a = str;
        this.b = i;
        this.c = list;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof B0) {
            B0 b0 = (B0) obj;
            if (this.a.equals(((W) b0).a)) {
                W w = (W) b0;
                if (this.b == w.b && this.c.equals(w.c)) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Thread{name=");
        sb.append(this.a);
        sb.append(", importance=");
        sb.append(this.b);
        sb.append(", frames=");
        return android.support.v4.media.session.a.n("}", sb, this.c);
    }
}
