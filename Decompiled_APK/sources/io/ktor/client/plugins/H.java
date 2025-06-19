package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class H {
    public static final org.slf4j.b a = AbstractC3189k7.d("io.ktor.client.plugins.HttpRequestLifecycle");
    public static final io.ktor.client.plugins.api.d b;

    static {
        com.sdk.growthbook.utils.a body = new com.sdk.growthbook.utils.a(12);
        Intrinsics.checkNotNullParameter("RequestLifecycle", "name");
        Intrinsics.checkNotNullParameter(body, "body");
        b = V6.a("RequestLifecycle", new io.ktor.client.plugins.api.b(2), body);
    }
}
