package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class k extends kotlin.jvm.internal.B {
    public static final k a = new k(com.quizlet.quizletandroid.ui.widgets.ui.theme.a.class, "widgetTrophy", "getWidgetTrophy(Lcom/quizlet/themes/AssemblyColors;)J", 1);

    @Override // kotlin.jvm.internal.B, kotlin.reflect.l
    public final Object get(Object obj) {
        com.quizlet.themes.b bVar = (com.quizlet.themes.b) obj;
        androidx.compose.runtime.B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.a.a;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        long jK = bVar.K();
        long jI = bVar.I();
        if (bVar.d) {
            jK = jI;
        }
        return new C0861v(jK);
    }
}
