package io.ktor.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final ConcurrentHashMap a = new ConcurrentHashMap();

    public final Object a(a key, Function0 block) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(block, "block");
        ConcurrentHashMap concurrentHashMap = this.a;
        Object obj = concurrentHashMap.get(key);
        if (obj != null) {
            return obj;
        }
        Object objInvoke = block.invoke();
        Object objPutIfAbsent = concurrentHashMap.putIfAbsent(key, objInvoke);
        if (objPutIfAbsent != null) {
            objInvoke = objPutIfAbsent;
        }
        Intrinsics.e(objInvoke, "null cannot be cast to non-null type T of io.ktor.util.ConcurrentSafeAttributes.computeIfAbsent");
        return objInvoke;
    }

    public final Object b(a key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Object objD = d(key);
        if (objD != null) {
            return objD;
        }
        throw new IllegalStateException("No instance for key " + key);
    }

    public final Map c() {
        return this.a;
    }

    public final Object d(a key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return c().get(key);
    }

    public final void e(a key, Object value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        c().put(key, value);
    }
}
