package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class u extends kotlin.jvm.internal.B {
    public static final u a = new u(com.quizlet.quizletandroid.ui.widgets.ui.theme.a.class, "widgetBackgroundLogo", "getWidgetBackgroundLogo(Lcom/quizlet/themes/AssemblyColors;)J", 1);

    @Override // kotlin.jvm.internal.B, kotlin.reflect.l
    public final Object get(Object obj) {
        com.quizlet.themes.b bVar = (com.quizlet.themes.b) obj;
        androidx.compose.runtime.B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.a.a;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        long jP = bVar.p();
        bVar.c.getClass();
        long j = com.quizlet.ui.resources.designsystem.generated.d.s;
        if (bVar.d) {
            jP = j;
        }
        return new C0861v(jP);
    }
}
