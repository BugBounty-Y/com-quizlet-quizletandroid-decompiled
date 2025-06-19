package com.quizlet.features.infra.folder.create.coursefolder.composable;

import androidx.compose.foundation.text.C0486e0;
import androidx.compose.ui.focus.s;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Q0 b;

    public /* synthetic */ g(Q0 q0, int i) {
        this.a = i;
        this.b = q0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Q0 q0;
        switch (this.a) {
            case 0:
                C0486e0 KeyboardActions = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions, "$this$KeyboardActions");
                Q0 q02 = this.b;
                if (q02 != null) {
                    ((C0957n0) q02).a();
                }
                break;
            default:
                s it2 = (s) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.a() && (q0 = this.b) != null) {
                    ((C0957n0) q0).b();
                }
                break;
        }
        return Unit.a;
    }
}
