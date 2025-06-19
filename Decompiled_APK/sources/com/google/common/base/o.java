package com.google.common.base;

import java.io.Serializable;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class o implements l, Serializable {
    public final Object a;

    public o(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof o)) {
            return false;
        }
        Object obj2 = this.a;
        Object obj3 = ((o) obj).a;
        return obj2 == obj3 || obj2.equals(obj3);
    }

    @Override // com.google.common.base.l
    public final Object get() {
        return this.a;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a});
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Suppliers.ofInstance("), this.a, ")");
    }
}
