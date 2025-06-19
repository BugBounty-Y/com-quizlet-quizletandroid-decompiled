package org.wordpress.aztec.spans;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.style.DynamicDrawableSpan;
import android.view.Gravity;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5167o extends AbstractC5156d implements C {
    public final C5146b d;
    public final ArrayList e;
    public WeakReference f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AbstractC5167o(Drawable drawable, C5146b attributes) {
        super(drawable);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.d = attributes;
        this.e = new ArrayList();
        this.f = new WeakReference(null);
        this.b = null;
    }

    public final void c(Drawable drawable) {
        ArrayList arrayList = this.e;
        if (kotlin.collections.B.i(arrayList) >= 0) {
            arrayList.remove(0);
        }
        if (drawable != null) {
            arrayList.ensureCapacity(1);
            arrayList.add(0, new Pair(drawable, 17));
            AbstractC5156d.b(drawable);
        }
    }

    @Override // org.wordpress.aztec.spans.AbstractC5156d, android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public final void draw(Canvas canvas, CharSequence text, int i, int i2, float f, int i3, int i4, int i5, Paint paint) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(paint, "paint");
        canvas.save();
        Drawable drawable = this.a;
        if (drawable != null) {
            if (((DynamicDrawableSpan) this).mVerticalAlignment == 1) {
                i3 -= paint.getFontMetricsInt().descent;
            }
            canvas.translate(f, i3);
            Intrinsics.d(drawable);
            drawable.draw(canvas);
        }
        ArrayList<Pair> arrayList = this.e;
        for (Pair pair : arrayList) {
            Drawable drawable2 = (Drawable) pair.a;
            int iIntValue = ((Number) pair.b).intValue();
            if (drawable != null && drawable2 != null) {
                Rect rect = new Rect(0, 0, drawable.getBounds().width(), drawable.getBounds().height());
                Rect rect2 = new Rect();
                Gravity.apply(iIntValue, drawable2.getBounds().width(), drawable2.getBounds().height(), rect, rect2);
                drawable2.setBounds(rect2.left, rect2.top, rect2.right, rect2.bottom);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Drawable drawable3 = (Drawable) ((Pair) it2.next()).a;
            if (drawable3 != null) {
                drawable3.draw(canvas);
            }
        }
        canvas.restore();
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.d;
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        T2.c(this, editable, i, i2);
    }

    public abstract String u();
}
