package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.ViewGroup;

/* renamed from: androidx.recyclerview.widget.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1383o0 extends ViewGroup.MarginLayoutParams {
    public F0 a;
    public final Rect b;
    public boolean c;
    public boolean d;

    public C1383o0(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.b = new Rect();
        this.c = true;
        this.d = false;
    }

    public C1383o0(int i, int i2) {
        super(i, i2);
        this.b = new Rect();
        this.c = true;
        this.d = false;
    }

    public C1383o0(ViewGroup.MarginLayoutParams marginLayoutParams) {
        super(marginLayoutParams);
        this.b = new Rect();
        this.c = true;
        this.d = false;
    }

    public C1383o0(ViewGroup.LayoutParams layoutParams) {
        super(layoutParams);
        this.b = new Rect();
        this.c = true;
        this.d = false;
    }

    public C1383o0(C1383o0 c1383o0) {
        super((ViewGroup.LayoutParams) c1383o0);
        this.b = new Rect();
        this.c = true;
        this.d = false;
    }
}
