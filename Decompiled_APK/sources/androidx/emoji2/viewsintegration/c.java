package androidx.emoji2.viewsintegration;

import android.text.InputFilter;
import android.text.Spanned;
import android.widget.TextView;
import androidx.emoji2.text.j;

/* loaded from: classes.dex */
public final class c implements InputFilter {
    public final TextView a;
    public androidx.compose.ui.text.platform.f b;

    public c(TextView textView) {
        this.a = textView;
    }

    @Override // android.text.InputFilter
    public final CharSequence filter(CharSequence charSequence, int i, int i2, Spanned spanned, int i3, int i4) {
        TextView textView = this.a;
        if (textView.isInEditMode()) {
            return charSequence;
        }
        int iB = j.a().b();
        if (iB != 0) {
            if (iB == 1) {
                if ((i4 == 0 && i3 == 0 && spanned.length() == 0 && charSequence == textView.getText()) || charSequence == null) {
                    return charSequence;
                }
                if (i != 0 || i2 != charSequence.length()) {
                    charSequence = charSequence.subSequence(i, i2);
                }
                return j.a().f(0, charSequence.length(), 0, charSequence);
            }
            if (iB != 3) {
                return charSequence;
            }
        }
        j jVarA = j.a();
        if (this.b == null) {
            this.b = new androidx.compose.ui.text.platform.f(textView, this);
        }
        jVarA.g(this.b);
        return charSequence;
    }
}
