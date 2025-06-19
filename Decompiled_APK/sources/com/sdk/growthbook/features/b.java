package com.sdk.growthbook.features;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ b(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return FeaturesDataSource.fetchFeatures$lambda$2(this.b, (Throwable) obj);
            case 1:
                return FeaturesDataSource.fetchRemoteEval$lambda$6(this.b, (Throwable) obj);
            default:
                kotlinx.io.a buffer = (kotlinx.io.a) obj;
                Intrinsics.checkNotNullParameter(buffer, "buffer");
                while (true) {
                    Intrinsics.checkNotNullParameter(buffer, "<this>");
                    if (buffer.u()) {
                        return Boolean.TRUE;
                    }
                    this.b.invoke(Byte.valueOf(buffer.readByte()));
                }
        }
    }
}
