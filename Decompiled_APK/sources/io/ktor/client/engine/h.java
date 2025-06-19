package io.ktor.client.engine;

import io.ktor.client.plugins.X;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import kotlin.collections.Z;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.L;
import kotlin.jvm.internal.U;
import kotlin.reflect.KTypeProjection;
import kotlin.reflect.q;

/* loaded from: classes3.dex */
public abstract class h {
    public static final io.ktor.util.a a;

    static {
        U u;
        C4950i c4950iA = K.a(Map.class);
        try {
            KTypeProjection.c.getClass();
            KTypeProjection kTypeProjection = KTypeProjection.d;
            C4950i c4950iA2 = K.a(g.class);
            List listSingletonList = Collections.singletonList(kTypeProjection);
            L l = K.a;
            l.getClass();
            KTypeProjection kTypeProjectionA = q.a(L.b(c4950iA2, listSingletonList));
            KTypeProjection kTypeProjectionA2 = q.a(K.c(Object.class));
            C4950i c4950iA3 = K.a(Map.class);
            List listAsList = Arrays.asList(kTypeProjectionA, kTypeProjectionA2);
            l.getClass();
            U uB = L.b(c4950iA3, listAsList);
            u = new U(uB.a, uB.b, uB.c | 2);
        } catch (Throwable unused) {
            u = null;
        }
        a = new io.ktor.util.a("EngineCapabilities", new io.ktor.util.reflect.a(c4950iA, u));
        Z.b(X.a);
    }
}
