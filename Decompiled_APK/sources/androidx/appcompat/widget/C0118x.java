package androidx.appcompat.widget;

import android.content.res.TypedArray;
import android.text.InputFilter;
import android.util.AttributeSet;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;

/* renamed from: androidx.appcompat.widget.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0118x {
    public final TextView a;
    public final androidx.webkit.internal.p b;

    public C0118x(TextView textView) {
        this.a = textView;
        this.b = new androidx.webkit.internal.p(textView);
    }

    public final InputFilter[] a(InputFilter[] inputFilterArr) {
        return ((AbstractC3099a7) this.b.b).c(inputFilterArr);
    }

    public final void b(AttributeSet attributeSet, int i) {
        TypedArray typedArrayObtainStyledAttributes = this.a.getContext().obtainStyledAttributes(attributeSet, androidx.appcompat.a.i, i, 0);
        try {
            boolean z = typedArrayObtainStyledAttributes.hasValue(14) ? typedArrayObtainStyledAttributes.getBoolean(14, true) : true;
            typedArrayObtainStyledAttributes.recycle();
            d(z);
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }

    public final void c(boolean z) {
        ((AbstractC3099a7) this.b.b).e(z);
    }

    public final void d(boolean z) {
        ((AbstractC3099a7) this.b.b).f(z);
    }
}
