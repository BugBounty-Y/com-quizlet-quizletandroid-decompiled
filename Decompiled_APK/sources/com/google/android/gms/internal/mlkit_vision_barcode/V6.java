package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V6 {
    public static final /* synthetic */ int a = 0;

    public static final io.ktor.client.plugins.api.d a(String name, Function0 createConfiguration, Function1 body) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(createConfiguration, "createConfiguration");
        Intrinsics.checkNotNullParameter(body, "body");
        return new io.ktor.client.plugins.api.d(name, createConfiguration, body);
    }

    public static boolean b(byte b) {
        return b > -65;
    }
}
