package com.quizlet.uicommon.util;

import android.text.TextPaint;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends com.quizlet.uicommon.ui.common.text.a {
    public final int a;
    public final int b;
    public boolean c;
    public final /* synthetic */ com.quizlet.ui.compose.modifiers.b d;

    public b(com.quizlet.ui.compose.modifiers.b bVar, int i, int i2) {
        this.d = bVar;
        this.a = i;
        this.b = i2;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View widget) {
        Intrinsics.checkNotNullParameter(widget, "widget");
        this.d.invoke(widget);
    }

    @Override // com.quizlet.uicommon.ui.common.text.a, android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint ds) {
        Intrinsics.checkNotNullParameter(ds, "ds");
        ds.setColor(this.c ? this.b : this.a);
    }
}
