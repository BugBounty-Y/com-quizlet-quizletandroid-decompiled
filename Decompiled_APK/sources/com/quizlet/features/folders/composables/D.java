package com.quizlet.features.folders.composables;

import androidx.compose.foundation.text.C0486e0;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class D implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.focus.h c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ D(Function1 function1, androidx.compose.ui.focus.h hVar, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = function1;
        this.c = hVar;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0486e0 KeyboardActions = (C0486e0) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(KeyboardActions, "$this$KeyboardActions");
                this.b.invoke((String) this.d.getValue());
                androidx.compose.ui.focus.h.a(this.c);
                break;
            default:
                Intrinsics.checkNotNullParameter(KeyboardActions, "$this$KeyboardActions");
                this.b.invoke((String) this.d.getValue());
                androidx.compose.ui.focus.h.a(this.c);
                break;
        }
        return Unit.a;
    }
}
