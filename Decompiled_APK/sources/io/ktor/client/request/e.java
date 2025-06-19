package io.ktor.client.request;

import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.U;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class e {
    public static final /* synthetic */ int a = 0;

    static {
        U uC;
        C4950i c4950iA = K.a(j.class);
        try {
            uC = K.c(j.class);
        } catch (Throwable unused) {
            uC = null;
        }
        io.ktor.util.reflect.a type = new io.ktor.util.reflect.a(c4950iA, uC);
        Intrinsics.checkNotNullParameter("ResponseAdapterAttributeKey", "name");
        Intrinsics.checkNotNullParameter(type, "type");
        if (StringsKt.O("ResponseAdapterAttributeKey")) {
            throw new IllegalArgumentException("Name can't be blank");
        }
    }
}
