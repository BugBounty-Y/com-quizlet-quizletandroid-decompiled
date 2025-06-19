package com.quizlet.assembly.compose.modals;

import android.view.KeyEvent;
import androidx.activity.L;
import androidx.activity.N;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class l implements Function1 {
    public final /* synthetic */ N a;
    public final /* synthetic */ x b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public l(N n, x xVar, InterfaceC0773a0 interfaceC0773a0) {
        this.a = n;
        this.b = xVar;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        L onBackPressedDispatcher;
        KeyEvent it2 = ((androidx.compose.ui.input.key.b) obj).a;
        Intrinsics.checkNotNullParameter(it2, "it");
        if (!androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.b(it2), androidx.compose.ui.input.key.a.b) || androidx.compose.ui.input.key.c.c(it2) != 1 || it2.isCanceled()) {
            return Boolean.FALSE;
        }
        x xVar = this.b;
        ((Function0) this.c.getValue()).invoke();
        xVar.c();
        N n = this.a;
        if (n != null && (onBackPressedDispatcher = n.getOnBackPressedDispatcher()) != null) {
            onBackPressedDispatcher.c();
        }
        return Boolean.TRUE;
    }
}
