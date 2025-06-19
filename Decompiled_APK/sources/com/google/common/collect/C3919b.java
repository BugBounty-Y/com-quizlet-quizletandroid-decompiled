package com.google.common.collect;

import com.google.common.base.Function;
import java.io.Serializable;
import java.util.Arrays;

/* renamed from: com.google.common.collect.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3919b extends w implements Serializable {
    public final Object a;
    public final w b;

    public C3919b(Function function, w wVar) {
        this.a = function;
        this.b = wVar;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [com.google.common.base.Function, java.lang.Object] */
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        ?? r0 = this.a;
        return this.b.compare(r0.apply(obj), r0.apply(obj2));
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.common.base.Function, java.lang.Object] */
    @Override // java.util.Comparator
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C3919b)) {
            return false;
        }
        C3919b c3919b = (C3919b) obj;
        return this.a.equals(c3919b.a) && this.b.equals(c3919b.b);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b});
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.b);
        sb.append(".onResultOf(");
        return android.support.v4.media.session.a.s(sb, this.a, ")");
    }
}
