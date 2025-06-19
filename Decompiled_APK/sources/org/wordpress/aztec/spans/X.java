package org.wordpress.aztec.spans;

import android.text.style.ImageSpan;
import android.text.style.ParagraphStyle;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class X extends ImageSpan implements ParagraphStyle, K {
    public static final Set d;
    public int a;
    public StringBuilder b;
    public W c;

    static {
        String[] elements = {"html", "body"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        d = C4933y.T(elements);
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.a = i;
    }
}
