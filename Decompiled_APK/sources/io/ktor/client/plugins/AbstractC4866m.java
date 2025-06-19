package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import kotlin.Unit;
import kotlin.jvm.internal.C4950i;

/* renamed from: io.ktor.client.plugins.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4866m {
    public static final io.ktor.util.a a;
    public static final io.ktor.util.a b;
    public static final io.ktor.client.plugins.api.d c;

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(Unit.class);
        kotlin.jvm.internal.U uC2 = null;
        try {
            uC = kotlin.jvm.internal.K.c(Unit.class);
        } catch (Throwable unused) {
            uC = null;
        }
        a = new io.ktor.util.a("SkipSaveBody", new io.ktor.util.reflect.a(c4950iA, uC));
        C4950i c4950iA2 = kotlin.jvm.internal.K.a(Unit.class);
        try {
            uC2 = kotlin.jvm.internal.K.c(Unit.class);
        } catch (Throwable unused2) {
        }
        b = new io.ktor.util.a("ResponseBodySaved", new io.ktor.util.reflect.a(c4950iA2, uC2));
        c = V6.a("DoubleReceivePlugin", C4865l.a, new com.sdk.growthbook.utils.a(8));
    }
}
