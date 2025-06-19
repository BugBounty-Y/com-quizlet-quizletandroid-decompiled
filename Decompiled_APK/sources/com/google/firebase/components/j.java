package com.google.firebase.components;

import com.google.android.gms.internal.mlkit_vision_common.y4;

/* loaded from: classes2.dex */
public final class j {
    public final q a;
    public final int b;
    public final int c;

    public j(int i, int i2, Class cls) {
        this(q.a(cls), i, i2);
    }

    public static j a(Class cls) {
        return new j(0, 1, cls);
    }

    public static j b(q qVar) {
        return new j(qVar, 1, 0);
    }

    public static j c(Class cls) {
        return new j(1, 0, cls);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a.equals(jVar.a) && this.b == jVar.b && this.c == jVar.c;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b) * 1000003) ^ this.c;
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder("Dependency{anInterface=");
        sb.append(this.a);
        sb.append(", type=");
        int i = this.b;
        sb.append(i == 1 ? "required" : i == 0 ? "optional" : "set");
        sb.append(", injection=");
        int i2 = this.c;
        if (i2 == 0) {
            str = "direct";
        } else if (i2 == 1) {
            str = "provider";
        } else {
            if (i2 != 2) {
                throw new AssertionError(android.support.v4.media.session.a.f(i2, "Unsupported injection: "));
            }
            str = "deferred";
        }
        return android.support.v4.media.session.a.t(sb, str, "}");
    }

    public j(q qVar, int i, int i2) {
        y4.b(qVar, "Null dependency anInterface.");
        this.a = qVar;
        this.b = i;
        this.c = i2;
    }
}
