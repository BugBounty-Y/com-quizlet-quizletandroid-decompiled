package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: io.ktor.client.plugins.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4857d {
    public static final io.ktor.util.a a;
    public static final io.ktor.util.a b;
    public static final io.ktor.client.plugins.api.d c;

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(io.ktor.client.content.a.class);
        kotlin.jvm.internal.U uC2 = null;
        try {
            uC = kotlin.jvm.internal.K.c(io.ktor.client.content.a.class);
        } catch (Throwable unused) {
            uC = null;
        }
        a = new io.ktor.util.a("UploadProgressListenerAttributeKey", new io.ktor.util.reflect.a(c4950iA, uC));
        C4950i c4950iA2 = kotlin.jvm.internal.K.a(io.ktor.client.content.a.class);
        try {
            uC2 = kotlin.jvm.internal.K.c(io.ktor.client.content.a.class);
        } catch (Throwable unused2) {
        }
        b = new io.ktor.util.a("DownloadProgressListenerAttributeKey", new io.ktor.util.reflect.a(c4950iA2, uC2));
        com.sdk.growthbook.utils.a body = new com.sdk.growthbook.utils.a(6);
        Intrinsics.checkNotNullParameter("BodyProgress", "name");
        Intrinsics.checkNotNullParameter(body, "body");
        c = V6.a("BodyProgress", new io.ktor.client.plugins.api.b(2), body);
    }
}
