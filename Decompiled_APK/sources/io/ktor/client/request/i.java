package io.ktor.client.request;

import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.U;

/* loaded from: classes3.dex */
public abstract class i {
    public static final io.ktor.util.a a;

    static {
        U uC;
        C4950i c4950iA = K.a(io.ktor.util.reflect.a.class);
        try {
            uC = K.c(io.ktor.util.reflect.a.class);
        } catch (Throwable unused) {
            uC = null;
        }
        a = new io.ktor.util.a("BodyTypeAttributeKey", new io.ktor.util.reflect.a(c4950iA, uC));
    }
}
