package com.google.android.material.textfield;

import android.content.res.Resources;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;
import androidx.core.view.V;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.AztecPreformatSpan;
import org.wordpress.aztec.spans.C5154b;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5172u;
import org.wordpress.aztec.spans.T;

/* loaded from: classes2.dex */
public final class u implements TextWatcher {
    public final /* synthetic */ int a = 0;
    public int b;
    public final Object c;
    public Object d;

    public u(AztecText aztecText, int i) {
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.b = i;
        this.c = new WeakReference(aztecText);
        this.d = new org.wordpress.aztec.watchers.h();
    }

    private final void a(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void b(int i, int i2, int i3, CharSequence charSequence) {
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) throws Resources.NotFoundException {
        switch (this.a) {
            case 0:
                TextInputLayout textInputLayout = (TextInputLayout) this.d;
                textInputLayout.u(!textInputLayout.K1, false);
                if (textInputLayout.k) {
                    textInputLayout.n(text);
                }
                if (textInputLayout.s) {
                    textInputLayout.v(text);
                }
                EditText editText = (EditText) this.c;
                int lineCount = editText.getLineCount();
                int i = this.b;
                if (lineCount != i) {
                    if (lineCount < i) {
                        WeakHashMap weakHashMap = V.a;
                        int minimumHeight = editText.getMinimumHeight();
                        int i2 = textInputLayout.D1;
                        if (minimumHeight != i2) {
                            editText.setMinimumHeight(i2);
                        }
                    }
                    this.b = lineCount;
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                Object[] spans = text.getSpans(0, text.length(), C5172u.class);
                Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                for (Object obj : spans) {
                    C5172u c5172u = (C5172u) obj;
                    text.setSpan(c5172u, text.getSpanStart(c5172u), text.getSpanEnd(c5172u), 33);
                }
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                this.d = new org.wordpress.aztec.watchers.h(text.toString(), 6);
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        AztecText aztecText;
        switch (this.a) {
            case 0:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                org.wordpress.aztec.watchers.h hVar = (org.wordpress.aztec.watchers.h) this.d;
                hVar.d = i2;
                Intrinsics.checkNotNullParameter(text, "<set-?>");
                hVar.c = text;
                org.wordpress.aztec.watchers.h hVar2 = (org.wordpress.aztec.watchers.h) this.d;
                hVar2.f = i3;
                hVar2.e = i;
                hVar2.a();
                if (((org.wordpress.aztec.watchers.h) this.d).b() && (aztecText = (AztecText) ((WeakReference) this.c).get()) != null && !aztecText.m && aztecText.y) {
                    org.wordpress.aztec.watchers.h hVar3 = (org.wordpress.aztec.watchers.h) this.d;
                    int i4 = hVar3.l;
                    int i5 = hVar3.g;
                    Editable text2 = aztecText.getText();
                    Intrinsics.checkNotNullParameter(text2, "text");
                    org.wordpress.aztec.watchers.h hVar4 = (org.wordpress.aztec.watchers.h) this.d;
                    int i6 = hVar4.l;
                    int i7 = hVar4.g;
                    Object[] spans = text2.getSpans(i6, i7, C5164l.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    boolean z = spans.length == 0;
                    Object[] spans2 = text2.getSpans(i6, i7, AztecPreformatSpan.class);
                    Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                    boolean z2 = spans2.length == 0;
                    Object[] spans3 = text2.getSpans(i6, i7, C5154b.class);
                    Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
                    boolean z3 = spans3.length == 0;
                    Object[] spans4 = text2.getSpans(i6, i7, C5160h.class);
                    Intrinsics.checkNotNullExpressionValue(spans4, "getSpans(...)");
                    boolean z4 = spans4.length == 0;
                    boolean z5 = (z4 || text2.length() <= i7 || text2.charAt(i7) != '\n') ? !z4 : false;
                    if (z && !z5 && z2 && z3) {
                        aztecText.getText().setSpan(new C5172u(this.b), i4, i5, 33);
                        T[] tArr = (T[]) aztecText.getText().getSpans(i4, i5, T.class);
                        Intrinsics.d(tArr);
                        if (tArr.length != 0) {
                            T t = (T) C4933y.A(tArr);
                            if (aztecText.getText().getSpanEnd(t) > i5) {
                                aztecText.getText().setSpan(t, aztecText.getText().getSpanStart(t), i5, aztecText.getText().getSpanFlags(t));
                                break;
                            }
                        }
                    }
                }
                break;
        }
    }

    public u(TextInputLayout textInputLayout, EditText editText) {
        this.d = textInputLayout;
        this.c = editText;
        this.b = editText.getLineCount();
    }
}
