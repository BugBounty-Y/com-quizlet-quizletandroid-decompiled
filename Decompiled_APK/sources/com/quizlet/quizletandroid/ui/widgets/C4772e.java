package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.widgets.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4772e extends kotlin.jvm.internal.B {
    public static final C4772e a = new C4772e(com.quizlet.quizletandroid.ui.widgets.ui.theme.a.class, "widgetBackgroundLogo", "getWidgetBackgroundLogo(Lcom/quizlet/themes/AssemblyColors;)J", 1);

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
