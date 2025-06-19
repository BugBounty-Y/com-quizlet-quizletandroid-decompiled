package androidx.compose.ui.text.platform.style;

import android.graphics.Shader;
import android.text.TextPaint;
import android.text.style.CharacterStyle;
import android.text.style.UpdateAppearance;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.E;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.geometry.e;
import androidx.compose.ui.graphics.T;
import androidx.compose.ui.text.platform.i;

/* loaded from: classes.dex */
public final class b extends CharacterStyle implements UpdateAppearance {
    public final T a;
    public final float b;
    public final InterfaceC0773a0 c = C0776c.z(new e(9205357640488583168L));
    public final E d = C0776c.q(new androidx.compose.ui.input.nestedscroll.b(this, 13));

    public b(T t, float f) {
        this.a = t;
        this.b = f;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        i.b(textPaint, this.b);
        textPaint.setShader((Shader) this.d.getValue());
    }
}
