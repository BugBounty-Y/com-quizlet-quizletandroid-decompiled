package androidx.emoji2.viewsintegration;

import android.text.Editable;
import androidx.emoji2.text.x;

/* loaded from: classes.dex */
public final class a extends Editable.Factory {
    public static final Object a = new Object();
    public static volatile a b;
    public static Class c;

    @Override // android.text.Editable.Factory
    public final Editable newEditable(CharSequence charSequence) {
        Class cls = c;
        return cls != null ? new x(cls, charSequence) : super.newEditable(charSequence);
    }
}
