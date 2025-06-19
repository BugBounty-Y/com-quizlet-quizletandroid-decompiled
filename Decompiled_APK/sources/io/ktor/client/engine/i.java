package io.ktor.client.engine;

import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.L;
import kotlin.jvm.internal.U;
import kotlin.reflect.KTypeProjection;
import kotlinx.coroutines.B;

/* loaded from: classes3.dex */
public abstract class i {
    public static final B a = new B("call-context");
    public static final io.ktor.util.a b;

    static {
        U uB;
        C4950i c4950iA = K.a(io.ktor.client.d.class);
        try {
            KTypeProjection.c.getClass();
            KTypeProjection kTypeProjection = KTypeProjection.d;
            C4950i c4950iA2 = K.a(io.ktor.client.d.class);
            List listSingletonList = Collections.singletonList(kTypeProjection);
            K.a.getClass();
            uB = L.b(c4950iA2, listSingletonList);
        } catch (Throwable unused) {
            uB = null;
        }
        b = new io.ktor.util.a("client-config", new io.ktor.util.reflect.a(c4950iA, uB));
    }
}
