package com.google.android.gms.internal.fido;

import java.io.Serializable;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.fido.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2942f implements Serializable {
    public final Object a;

    public C2942f(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2942f) {
            return AbstractC2937a.h(this.a, ((C2942f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a});
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Suppliers.ofInstance(", this.a.toString(), ")");
    }
}
