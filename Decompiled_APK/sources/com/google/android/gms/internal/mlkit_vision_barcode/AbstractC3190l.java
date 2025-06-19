package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Jt;
import java.util.Map;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3190l {
    public transient C3136f a;
    public transient Jt b;

    public final Map a() {
        Jt jt = this.b;
        if (jt != null) {
            return jt;
        }
        C3199m c3199m = (C3199m) this;
        Jt jt2 = new Jt(c3199m, c3199m.c, 1);
        this.b = jt2;
        return jt2;
    }

    public final Set b() {
        C3136f c3136f = this.a;
        if (c3136f != null) {
            return c3136f;
        }
        C3199m c3199m = (C3199m) this;
        C3136f c3136f2 = new C3136f(c3199m, c3199m.c);
        this.a = c3136f2;
        return c3136f2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof AbstractC3190l) {
            return a().equals(((AbstractC3190l) obj).a());
        }
        return false;
    }

    public final int hashCode() {
        return ((r) ((Jt) a()).d).hashCode();
    }

    public final String toString() {
        return ((r) ((Jt) a()).d).toString();
    }
}
