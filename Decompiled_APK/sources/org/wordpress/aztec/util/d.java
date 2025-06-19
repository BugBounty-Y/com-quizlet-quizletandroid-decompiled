package org.wordpress.aztec.util;

import android.text.Spannable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final Spannable a;
    public final Object b;
    public int c;
    public int d;
    public int e;

    public d(Spannable spannable, Object obj) {
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        this.a = spannable;
        this.b = obj;
        this.c = -1;
        this.d = -1;
        this.e = -1;
    }

    public final int a() {
        return this.a.getSpanEnd(this.b);
    }

    public final int b() {
        return this.a.getSpanStart(this.b);
    }

    public final void c() {
        this.c = b();
        this.d = a();
        this.e = this.a.getSpanFlags(this.b);
        this.a.removeSpan(this.b);
    }

    public final void d(int i) {
        e(this.b, b(), i, this.a.getSpanFlags(this.b));
    }

    public final void e(Object obj, int i, int i2, int i3) {
        Spannable spannable = this.a;
        if (b.e(spannable, i, i2, i3)) {
            return;
        }
        spannable.setSpan(obj, i, i2, i3);
    }
}
