package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.reflect.KTypeProjection;

/* loaded from: classes3.dex */
public abstract class M {
    public static final org.slf4j.b a;
    public static final com.quizlet.quizletandroid.ui.login.di.a b;
    public static final io.ktor.client.plugins.api.d c;
    public static final io.ktor.util.a d;
    public static final io.ktor.util.a e;
    public static final io.ktor.util.a f;
    public static final io.ktor.util.a g;
    public static final io.ktor.util.a h;

    static {
        kotlin.jvm.internal.U uC;
        kotlin.jvm.internal.U uD;
        kotlin.jvm.internal.U uD2;
        kotlin.jvm.internal.U uD3;
        Class cls = Boolean.TYPE;
        Class cls2 = Integer.TYPE;
        a = AbstractC3189k7.d("io.ktor.client.plugins.HttpRequestRetry");
        b = new com.quizlet.quizletandroid.ui.login.di.a(5);
        c = V6.a("RetryFeature", K.a, new com.sdk.growthbook.utils.a(13));
        C4950i c4950iA = kotlin.jvm.internal.K.a(Integer.class);
        kotlin.jvm.internal.U uD4 = null;
        try {
            uC = kotlin.jvm.internal.K.c(cls2);
        } catch (Throwable unused) {
            uC = null;
        }
        d = new io.ktor.util.a("MaxRetriesPerRequestAttributeKey", new io.ktor.util.reflect.a(c4950iA, uC));
        C4950i c4950iA2 = kotlin.jvm.internal.K.a(kotlin.jvm.functions.c.class);
        try {
            kotlin.reflect.q qVar = KTypeProjection.c;
            kotlin.jvm.internal.U uC2 = kotlin.jvm.internal.K.c(Q.class);
            qVar.getClass();
            uD = kotlin.jvm.internal.K.d(kotlin.jvm.functions.c.class, kotlin.reflect.q.a(uC2), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(io.ktor.client.request.b.class)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(io.ktor.client.statement.b.class)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(cls)));
        } catch (Throwable unused2) {
            uD = null;
        }
        e = new io.ktor.util.a("ShouldRetryPerRequestAttributeKey", new io.ktor.util.reflect.a(c4950iA2, uD));
        C4950i c4950iA3 = kotlin.jvm.internal.K.a(kotlin.jvm.functions.c.class);
        try {
            kotlin.reflect.q qVar2 = KTypeProjection.c;
            kotlin.jvm.internal.U uC3 = kotlin.jvm.internal.K.c(Q.class);
            qVar2.getClass();
            uD2 = kotlin.jvm.internal.K.d(kotlin.jvm.functions.c.class, kotlin.reflect.q.a(uC3), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(io.ktor.client.request.c.class)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(Throwable.class)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(cls)));
        } catch (Throwable unused3) {
            uD2 = null;
        }
        f = new io.ktor.util.a("ShouldRetryOnExceptionPerRequestAttributeKey", new io.ktor.util.reflect.a(c4950iA3, uD2));
        C4950i c4950iA4 = kotlin.jvm.internal.K.a(Function2.class);
        try {
            kotlin.reflect.q qVar3 = KTypeProjection.c;
            kotlin.jvm.internal.U uC4 = kotlin.jvm.internal.K.c(P.class);
            qVar3.getClass();
            uD3 = kotlin.jvm.internal.K.d(Function2.class, kotlin.reflect.q.a(uC4), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(io.ktor.client.request.c.class)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(Unit.class)));
        } catch (Throwable unused4) {
            uD3 = null;
        }
        g = new io.ktor.util.a("ModifyRequestPerRequestAttributeKey", new io.ktor.util.reflect.a(c4950iA4, uD3));
        C4950i c4950iA5 = kotlin.jvm.internal.K.a(Function2.class);
        try {
            kotlin.reflect.q qVar4 = KTypeProjection.c;
            kotlin.jvm.internal.U uC5 = kotlin.jvm.internal.K.c(N.class);
            qVar4.getClass();
            uD4 = kotlin.jvm.internal.K.d(Function2.class, kotlin.reflect.q.a(uC5), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(cls2)), kotlin.reflect.q.a(kotlin.jvm.internal.K.c(Long.TYPE)));
        } catch (Throwable unused5) {
        }
        h = new io.ktor.util.a("RetryDelayPerRequestAttributeKey", new io.ktor.util.reflect.a(c4950iA5, uD4));
    }
}
