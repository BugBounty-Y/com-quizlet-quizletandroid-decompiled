package io.ktor.util;

import com.quizlet.search.composables.E;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends LinkedHashMap {
    public final E a;
    public final com.sdk.growthbook.utils.a b;
    public final int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(E supplier, com.sdk.growthbook.utils.a close, int i) {
        super(10, 0.75f, true);
        Intrinsics.checkNotNullParameter(supplier, "supplier");
        Intrinsics.checkNotNullParameter(close, "close");
        this.a = supplier;
        this.b = close;
        this.c = i;
    }

    @Override // java.util.LinkedHashMap, java.util.HashMap, java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        if (this.c == 0) {
            return this.a.invoke(obj);
        }
        synchronized (this) {
            Object obj2 = super.get(obj);
            if (obj2 != null) {
                return obj2;
            }
            Object objInvoke = this.a.invoke(obj);
            put(obj, objInvoke);
            return objInvoke;
        }
    }

    @Override // java.util.LinkedHashMap
    public final boolean removeEldestEntry(Map.Entry eldest) {
        Intrinsics.checkNotNullParameter(eldest, "eldest");
        boolean z = super.size() > this.c;
        if (z) {
            this.b.invoke(eldest.getValue());
        }
        return z;
    }
}
