package com.quizlet.local.cache;

import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class g implements com.quizlet.cache.a {
    public final long a;
    public final LinkedHashMap b;

    public g(long j) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = j;
        this.b = new LinkedHashMap();
    }

    @Override // com.quizlet.cache.a
    public final void a(Object obj, Object obj2) {
        if (obj2 == null) {
            b(obj);
        } else {
            this.b.put(obj, new f(com.quizlet.time.b.a(), obj2));
        }
    }

    @Override // com.quizlet.cache.a
    public final void b(Object obj) {
        this.b.remove(obj);
    }

    @Override // com.quizlet.cache.a
    public final Object get(Object obj) {
        f fVar = (f) this.b.get(obj);
        if (fVar != null && com.quizlet.time.b.a() - fVar.a < this.a) {
            return fVar.b;
        }
        b(obj);
        return null;
    }
}
