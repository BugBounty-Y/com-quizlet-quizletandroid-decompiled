package androidx.emoji2.text;

import android.text.TextPaint;

/* loaded from: classes.dex */
public final class d {
    public static final ThreadLocal b = new ThreadLocal();
    public final TextPaint a;

    public d() {
        TextPaint textPaint = new TextPaint();
        this.a = textPaint;
        textPaint.setTextSize(10.0f);
    }
}
