package androidx.constraintlayout.compose;

import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final Object a;
    public final Object b;
    public final d c;
    public final c d;
    public final d e;
    public final c f;

    public b(Object obj) {
        this.a = obj;
        new LinkedHashMap();
        this.b = obj;
        this.c = new d(obj, -2, this);
        this.d = new c(obj, 0, this);
        this.e = new d(obj, -1, this);
        this.f = new c(obj, 1, this);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return Intrinsics.b(this.b, ((b) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }
}
