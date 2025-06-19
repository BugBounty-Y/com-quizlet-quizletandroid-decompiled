package com.quizlet.partskit.widgets;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class EllipsizedSubstringTextView extends QTextView {
    public final SpannableStringBuilder a;
    public CharSequence b;
    public String c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public EllipsizedSubstringTextView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (StringsKt.O(this.b)) {
            return;
        }
        int lineStart = getLayout().getLineStart(getLayout().getLineCount() - 1);
        CharSequence text = getText();
        Intrinsics.checkNotNullExpressionValue(text, "getText(...)");
        CharSequence charSequenceSubSequence = getText().subSequence(lineStart, StringsKt.J(text) + 1);
        float width = getLayout().getWidth();
        if (Intrinsics.b(TextUtils.ellipsize(charSequenceSubSequence, getPaint(), width, getEllipsize()), charSequenceSubSequence)) {
            return;
        }
        TextPaint paint = getPaint();
        String str = this.c;
        CharSequence charSequence = this.b;
        StringBuilder sb = new StringBuilder();
        sb.append((Object) str);
        sb.append((Object) charSequence);
        CharSequence charSequenceEllipsize = TextUtils.ellipsize(charSequenceSubSequence, getPaint(), (width - paint.measureText(sb.toString())) * 0.99f, getEllipsize());
        CharSequence charSequenceSubSequence2 = getText().subSequence(0, lineStart);
        SpannableStringBuilder spannableStringBuilder = this.a;
        spannableStringBuilder.clear();
        setText(spannableStringBuilder.append(charSequenceSubSequence2).append(charSequenceEllipsize).append((CharSequence) this.c).append(this.b));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public EllipsizedSubstringTextView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public EllipsizedSubstringTextView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        this.a = new SpannableStringBuilder();
        this.b = "";
        this.c = "";
    }
}
