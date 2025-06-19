package io.ktor.client.plugins;

import com.quizlet.ui.compose.C4830x;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class K extends C4956o implements Function0 {
    public static final K a = new K(0, J.class, "<init>", "<init>()V", 0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        J j = new J();
        j.d = new C4830x(9, (byte) 0);
        j.e = new I(2, null);
        com.perimeterx.mobile_sdk.api_data.h block = new com.perimeterx.mobile_sdk.api_data.h(3);
        Intrinsics.checkNotNullParameter(block, "block");
        j.f = 3;
        Intrinsics.checkNotNullParameter(block, "<set-?>");
        j.a = block;
        com.perimeterx.mobile_sdk.api_data.h block2 = new com.perimeterx.mobile_sdk.api_data.h(2);
        Intrinsics.checkNotNullParameter(block2, "block");
        j.f = 3;
        Intrinsics.checkNotNullParameter(block2, "<set-?>");
        j.b = block2;
        C4830x block3 = new C4830x(j);
        Intrinsics.checkNotNullParameter(block3, "block");
        com.quizlet.features.questiontypes.written.ui.f fVar = new com.quizlet.features.questiontypes.written.ui.f(block3, 1);
        Intrinsics.checkNotNullParameter(fVar, "<set-?>");
        j.c = fVar;
        return j;
    }
}
