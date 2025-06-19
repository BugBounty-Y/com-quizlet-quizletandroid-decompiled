package com.quizlet.uicommon.ui.common.text;

import android.text.TextPaint;
import android.text.style.ClickableSpan;

/* loaded from: classes3.dex */
public abstract class a extends ClickableSpan {
    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        textPaint.setUnderlineText(false);
    }
}
