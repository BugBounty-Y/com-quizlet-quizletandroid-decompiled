package androidx.appcompat.widget;

import android.graphics.Typeface;
import android.os.Build;
import android.widget.TextView;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class U extends androidx.core.content.res.b {
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;
    public final /* synthetic */ WeakReference j;
    public final /* synthetic */ Z k;

    public U(Z z, int i, int i2, WeakReference weakReference) {
        this.k = z;
        this.h = i;
        this.i = i2;
        this.j = weakReference;
    }

    @Override // androidx.core.content.res.b
    public final void i(int i) {
    }

    @Override // androidx.core.content.res.b
    public final void j(Typeface typeface) {
        int i;
        if (Build.VERSION.SDK_INT >= 28 && (i = this.h) != -1) {
            typeface = Y.a(typeface, i, (this.i & 2) != 0);
        }
        Z z = this.k;
        if (z.m) {
            z.l = typeface;
            TextView textView = (TextView) this.j.get();
            if (textView != null) {
                if (textView.isAttachedToWindow()) {
                    textView.post(new V(textView, typeface, z.j, 0));
                } else {
                    textView.setTypeface(typeface, z.j);
                }
            }
        }
    }
}
