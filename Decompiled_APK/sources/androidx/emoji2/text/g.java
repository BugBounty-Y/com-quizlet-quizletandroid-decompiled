package androidx.emoji2.text;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.Y;

/* loaded from: classes.dex */
public abstract class g {
    public int a;
    public final Object b;
    public final Object c;

    public g(AbstractC1381n0 abstractC1381n0) {
        this.a = Integer.MIN_VALUE;
        this.c = new Rect();
        this.b = abstractC1381n0;
    }

    public static g a(AbstractC1381n0 abstractC1381n0, int i) {
        if (i == 0) {
            return new Y(abstractC1381n0, 0);
        }
        if (i == 1) {
            return new Y(abstractC1381n0, 1);
        }
        throw new IllegalArgumentException("invalid orientation");
    }

    public abstract int b(View view);

    public abstract int c(View view);

    public abstract int d(View view);

    public abstract int e(View view);

    public abstract int f();

    public abstract int g();

    public abstract int h();

    public abstract int i();

    public abstract int j();

    public abstract int k();

    public abstract int l();

    public abstract int m(View view);

    public abstract int n(View view);

    public abstract void o(int i);

    public g(i iVar) {
        this.a = 0;
        this.c = new d();
        this.b = iVar;
    }
}
