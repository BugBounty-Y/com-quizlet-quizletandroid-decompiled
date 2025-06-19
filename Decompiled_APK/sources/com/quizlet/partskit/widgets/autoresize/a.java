package com.quizlet.partskit.widgets.autoresize;

import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import android.text.StaticLayout;
import android.text.TextPaint;
import com.quizlet.richtext.ui.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final d a;
    public float b;
    public float c;
    public boolean d;
    public float e;
    public float f;
    public float g;
    public boolean h;
    public int i;
    public int j;

    public a(d textView, d textResizeListener) {
        Intrinsics.checkNotNullParameter(textView, "textView");
        Intrinsics.checkNotNullParameter(textResizeListener, "textResizeListener");
        this.a = textView;
        this.e = 20.0f;
        this.f = 1.0f;
        this.h = true;
    }

    public final SpannableStringBuilder a(int i, CharSequence charSequence) {
        CharSequence string;
        CharSequence text = this.a.getText();
        SpannedString spannedString = text instanceof SpannedString ? (SpannedString) text : null;
        if (spannedString == null || (string = spannedString.subSequence(0, i)) == null) {
            string = charSequence.subSequence(0, i).toString();
        }
        SpannableStringBuilder spannableStringBuilderAppend = new SpannableStringBuilder(string).append((CharSequence) "…");
        Intrinsics.checkNotNullExpressionValue(spannableStringBuilderAppend, "append(...)");
        return spannableStringBuilderAppend;
    }

    public final int b(CharSequence charSequence, TextPaint textPaint, int i, float f) {
        TextPaint textPaint2 = new TextPaint(textPaint);
        textPaint2.setTextSize(f);
        return new StaticLayout(charSequence, textPaint2, i, Layout.Alignment.ALIGN_NORMAL, this.f, this.g, true).getHeight();
    }
}
