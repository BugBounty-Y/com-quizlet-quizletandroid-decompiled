package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import kotlin.Unit;
import kotlin.jvm.internal.C4950i;

/* renamed from: io.ktor.client.plugins.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4859f {
    public static final io.ktor.util.a a;
    public static final org.slf4j.b b;

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(Unit.class);
        try {
            uC = kotlin.jvm.internal.K.c(Unit.class);
        } catch (Throwable unused) {
            uC = null;
        }
        a = new io.ktor.util.a("ValidateMark", new io.ktor.util.reflect.a(c4950iA, uC));
        b = AbstractC3189k7.d("io.ktor.client.plugins.DefaultResponseValidation");
    }
}
