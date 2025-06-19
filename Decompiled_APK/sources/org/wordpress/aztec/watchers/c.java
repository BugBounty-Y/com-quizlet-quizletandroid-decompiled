package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.TextWatcher;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import java.lang.ref.WeakReference;
import java.util.LinkedHashSet;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.C5174w;
import org.wordpress.aztec.spans.G;

/* loaded from: classes3.dex */
public final class c implements TextWatcher {
    public final WeakReference a;
    public boolean b;
    public int c;
    public int d;

    public c(AztecText aztecText) {
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.a = new WeakReference(aztecText);
    }

    public final void a(int i) {
        Editable text;
        AztecText aztecText = (AztecText) this.a.get();
        if (aztecText == null || (text = aztecText.getText()) == null) {
            return;
        }
        text.insert(i, C2.h);
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        int i = this.c;
        int i2 = this.d;
        AztecText aztecText = (AztecText) this.a.get();
        if (aztecText == null || aztecText.m) {
            return;
        }
        Object[] spans = aztecText.getText().getSpans(0, 0, C5174w.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        if (spans.length == 0) {
            int i3 = i2 + i;
            G[] gArr = (G[]) aztecText.getText().getSpans(i2, i3, G.class);
            Intrinsics.d(gArr);
            Object[] spans2 = aztecText.getText().getSpans(i2, i2, G.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            G[] gArr2 = (G[]) C4930v.s(gArr, spans2);
            Object[] spans3 = aztecText.getText().getSpans(i3, i3, G.class);
            Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
            G[] gArr3 = (G[]) C4930v.s(gArr2, spans3);
            Intrinsics.checkNotNullParameter(gArr3, "<this>");
            Intrinsics.checkNotNullParameter(gArr3, "<this>");
            LinkedHashSet linkedHashSet = new LinkedHashSet(U.a(gArr3.length));
            C4933y.L(gArr3, linkedHashSet);
            for (G g : CollectionsKt.w0(linkedHashSet)) {
                Editable spannable = aztecText.getText();
                Intrinsics.d(g);
                Intrinsics.checkNotNullParameter(spannable, "spannable");
                if (spannable.getSpanStart(g) != -1) {
                    int spanStart = spannable.getSpanStart(g);
                    char c = C2.g;
                    boolean z = spanStart > 0 && aztecText.getText().charAt(spannable.getSpanStart(g) - 1) != c;
                    boolean z2 = spannable.getSpanEnd(g) < aztecText.length() && aztecText.getText().charAt(spannable.getSpanEnd(g)) != c;
                    C5174w c5174w = new C5174w();
                    aztecText.getText().setSpan(c5174w, 0, 0, 17);
                    if (z) {
                        int spanStart2 = spannable.getSpanStart(g);
                        if (i <= 0 && this.b) {
                            int i4 = spanStart2 - 1;
                            aztecText.getText().delete(i4, spanStart2);
                            if (spanStart2 > 1 && aztecText.getText().charAt(spanStart2 - 2) != c) {
                                a(i4);
                            }
                            aztecText.setSelection(i4);
                        } else {
                            a(spanStart2);
                            aztecText.setSelection(spanStart2);
                        }
                    }
                    if (z2) {
                        if (i > 0) {
                            a(spannable.getSpanEnd(g));
                        } else {
                            aztecText.getText().delete(spannable.getSpanStart(g), spannable.getSpanEnd(g));
                        }
                    }
                    aztecText.getText().removeSpan(c5174w);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // android.text.TextWatcher
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void beforeTextChanged(java.lang.CharSequence r1, int r2, int r3, int r4) {
        /*
            r0 = this;
            java.lang.String r4 = "text"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r4)
            if (r3 <= 0) goto L13
            int r2 = r2 + r3
            r3 = 1
            int r2 = r2 - r3
            char r1 = r1.charAt(r2)
            char r2 = com.google.android.gms.internal.mlkit_vision_camera.C2.g
            if (r1 != r2) goto L13
            goto L14
        L13:
            r3 = 0
        L14:
            r0.b = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.watchers.c.beforeTextChanged(java.lang.CharSequence, int, int, int):void");
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.c = i3;
        this.d = i;
    }
}
