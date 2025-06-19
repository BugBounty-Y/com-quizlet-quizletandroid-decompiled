package com.quizlet.richtext.ui;

import android.content.Context;
import android.util.AttributeSet;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationTargetException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public class d extends e {
    public final com.quizlet.partskit.widgets.autoresize.a b;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public d(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final boolean getAddEllipsis() {
        return this.b.h;
    }

    @NotNull
    public final com.quizlet.partskit.widgets.autoresize.a getHelper() {
        return this.b;
    }

    public final float getMaxTextSize() {
        return this.b.c;
    }

    public final float getMinTextSize() {
        return this.b.e;
    }

    public final com.quizlet.partskit.widgets.autoresize.b getTextResizeListener() {
        return null;
    }

    public void j() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        float f = this.b.b;
        if (f > DefinitionKt.NO_Float_VALUE) {
            super.setTextSize(0, f);
            setMaxTextSize(f);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x00db  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0152  */
    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onLayout(boolean r18, int r19, int r20, int r21, int r22) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 375
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.richtext.ui.d.onLayout(boolean, int, int, int, int):void");
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        if (i == i3 && i2 == i4) {
            return;
        }
        com.quizlet.partskit.widgets.autoresize.a aVar = this.b;
        aVar.d = true;
        aVar.a.setVisibility(4);
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(text, "text");
        super.onTextChanged(text, i, i2, i3);
        com.quizlet.partskit.widgets.autoresize.a aVar = this.b;
        if (aVar != null) {
            aVar.d = true;
            aVar.a.setVisibility(4);
            j();
        }
    }

    public final void setAddEllipsis(boolean z) {
        this.b.h = z;
    }

    @Override // android.widget.TextView
    public final void setLineSpacing(float f, float f2) {
        super.setLineSpacing(f, f2);
        com.quizlet.partskit.widgets.autoresize.a aVar = this.b;
        aVar.f = f2;
        aVar.g = f;
    }

    public final void setMaxTextSize(float f) {
        this.b.c = f;
        requestLayout();
        invalidate();
    }

    public final void setTextResizeListener(com.quizlet.partskit.widgets.autoresize.b bVar) {
    }

    @Override // android.widget.TextView
    public void setTextSize(float f) {
        super.setTextSize(f);
        this.b.b = getTextSize();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public d(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        this.b = new com.quizlet.partskit.widgets.autoresize.a(this, this);
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView
    public final void setTextSize(int i, float f) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        super.setTextSize(i, f);
        this.b.b = getTextSize();
    }
}
