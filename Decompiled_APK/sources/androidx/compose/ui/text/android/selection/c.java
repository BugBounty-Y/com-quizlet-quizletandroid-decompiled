package androidx.compose.ui.text.android.selection;

import android.text.TextPaint;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;

/* loaded from: classes.dex */
public final class c extends AbstractC3223o5 {
    public final CharSequence b;
    public final TextPaint c;

    public c(CharSequence charSequence, TextPaint textPaint) {
        this.b = charSequence;
        this.c = textPaint;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5
    public final int d(int i) {
        CharSequence charSequence = this.b;
        return this.c.getTextRunCursor(charSequence, 0, charSequence.length(), false, i, 0);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5
    public final int g(int i) {
        CharSequence charSequence = this.b;
        return this.c.getTextRunCursor(charSequence, 0, charSequence.length(), false, i, 2);
    }
}
