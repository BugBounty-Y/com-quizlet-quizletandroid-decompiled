package com.quizlet.quizletandroid.initializers.app;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.quizletandroid.u;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class LockScreenRotationInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(d.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        u uVar = (u) ((d) objB);
        E.A(uVar.Q(), null, null, new f(uVar, null), 3);
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
