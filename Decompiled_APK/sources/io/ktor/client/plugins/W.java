package io.ktor.client.plugins;

import java.util.ArrayList;
import kotlin.jvm.internal.C4950i;

/* loaded from: classes3.dex */
public final class W {
    public static final C4854a c = new C4854a(6);
    public static final io.ktor.util.a d;
    public final int a;
    public final ArrayList b = new ArrayList();

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(W.class);
        try {
            uC = kotlin.jvm.internal.K.c(W.class);
        } catch (Throwable unused) {
            uC = null;
        }
        d = new io.ktor.util.a("HttpSend", new io.ktor.util.reflect.a(c4950iA, uC));
    }

    public W(int i) {
        this.a = i;
    }
}
