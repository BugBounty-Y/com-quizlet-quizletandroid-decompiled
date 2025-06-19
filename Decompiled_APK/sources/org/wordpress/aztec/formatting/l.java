package org.wordpress.aztec.formatting;

import android.content.Context;
import android.text.Editable;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import androidx.compose.animation.core.J0;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.C5149e;
import org.wordpress.aztec.G;
import org.wordpress.aztec.spans.AztecBackgroundColorSpan;
import org.wordpress.aztec.spans.AztecStrikethroughSpan;
import org.wordpress.aztec.spans.AztecStyleBoldSpan;
import org.wordpress.aztec.spans.AztecStyleCiteSpan;
import org.wordpress.aztec.spans.AztecStyleEmphasisSpan;
import org.wordpress.aztec.spans.AztecStyleItalicSpan;
import org.wordpress.aztec.spans.AztecStyleSpan;
import org.wordpress.aztec.spans.AztecStyleStrongSpan;
import org.wordpress.aztec.spans.AztecUnderlineSpan;
import org.wordpress.aztec.spans.C5154b;
import org.wordpress.aztec.spans.C5174w;
import org.wordpress.aztec.spans.F;
import org.wordpress.aztec.spans.H;
import org.wordpress.aztec.spans.HighlightSpan;
import org.wordpress.aztec.spans.S;
import org.wordpress.aztec.x;

/* loaded from: classes3.dex */
public final class l extends J0 {
    public final j c;
    public final k d;
    public Integer e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(AztecText editor, j codeStyle, k highlightStyle) {
        super(editor);
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(codeStyle, "codeStyle");
        Intrinsics.checkNotNullParameter(highlightStyle, "highlightStyle");
        this.c = codeStyle;
        this.d = highlightStyle;
    }

    public static void U(l lVar, G g, int i, int i2, int i3) {
        if ((i3 & 2) != 0) {
            i = ((AztecText) lVar.b).getSelectionStart();
        }
        if ((i3 & 4) != 0) {
            i2 = ((AztecText) lVar.b).getSelectionEnd();
        }
        lVar.T(g, i, i2, new C5146b());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static boolean X(H firstSpan, H secondSpan) {
        Intrinsics.checkNotNullParameter(firstSpan, "firstSpan");
        Intrinsics.checkNotNullParameter(secondSpan, "secondSpan");
        return ((firstSpan instanceof StyleSpan) && (secondSpan instanceof StyleSpan)) ? ((StyleSpan) firstSpan).getStyle() == ((StyleSpan) secondSpan).getStyle() : ((firstSpan instanceof AztecBackgroundColorSpan) && (secondSpan instanceof AztecBackgroundColorSpan)) ? ((AztecBackgroundColorSpan) firstSpan).getBackgroundColor() == ((AztecBackgroundColorSpan) secondSpan).getBackgroundColor() : firstSpan.getClass().equals(secondSpan.getClass());
    }

    public static x e0(H span) {
        Intrinsics.checkNotNullParameter(span, "span");
        Class<?> cls = span.getClass();
        if (cls.equals(AztecStyleBoldSpan.class)) {
            return x.k;
        }
        if (cls.equals(AztecStyleStrongSpan.class)) {
            return x.l;
        }
        if (cls.equals(AztecStyleItalicSpan.class)) {
            return x.m;
        }
        if (cls.equals(AztecStyleEmphasisSpan.class)) {
            return x.n;
        }
        if (cls.equals(AztecStyleCiteSpan.class)) {
            return x.o;
        }
        if (cls.equals(AztecStrikethroughSpan.class)) {
            return x.q;
        }
        if (cls.equals(AztecUnderlineSpan.class)) {
            return x.p;
        }
        if (cls.equals(C5154b.class)) {
            return x.F;
        }
        if (cls.equals(AztecBackgroundColorSpan.class)) {
            return x.G;
        }
        if (cls.equals(S.class)) {
            return x.H;
        }
        if (cls.equals(HighlightSpan.class)) {
            return x.I;
        }
        return null;
    }

    public final void T(G g, int i, int i2, C5146b c5146b) {
        H h;
        H h2;
        AztecText aztecText;
        int i3;
        H hZ = Z(g);
        hZ.r(c5146b);
        if (i >= i2) {
            return;
        }
        x xVar = x.G;
        AztecText aztecText2 = (AztecText) this.b;
        if (g == xVar) {
            int selectionStart = aztecText2.getSelectionStart();
            int selectionEnd = aztecText2.getSelectionEnd();
            AztecBackgroundColorSpan[] aztecBackgroundColorSpanArr = (AztecBackgroundColorSpan[]) u().getSpans(selectionStart, selectionEnd, AztecBackgroundColorSpan.class);
            Intrinsics.d(aztecBackgroundColorSpanArr);
            int length = aztecBackgroundColorSpanArr.length;
            int i4 = 0;
            while (i4 < length) {
                AztecBackgroundColorSpan aztecBackgroundColorSpan = aztecBackgroundColorSpanArr[i4];
                if (aztecBackgroundColorSpan != null) {
                    int spanStart = u().getSpanStart(aztecBackgroundColorSpan);
                    int spanEnd = u().getSpanEnd(aztecBackgroundColorSpan);
                    int backgroundColor = aztecBackgroundColorSpan.getBackgroundColor();
                    u().removeSpan(aztecBackgroundColorSpan);
                    if (selectionEnd < spanEnd) {
                        aztecText = aztecText2;
                        i3 = 33;
                        u().setSpan(new AztecBackgroundColorSpan(backgroundColor), selectionEnd, spanEnd, 33);
                    } else {
                        aztecText = aztecText2;
                        i3 = 33;
                    }
                    if (selectionStart > spanStart) {
                        u().setSpan(new AztecBackgroundColorSpan(backgroundColor), spanStart, selectionStart, i3);
                    }
                } else {
                    aztecText = aztecText2;
                }
                i4++;
                aztecText2 = aztecText;
            }
        }
        AztecText aztecText3 = aztecText2;
        if (i >= 1) {
            H[] hArr = (H[]) u().getSpans(i - 1, i, H.class);
            Intrinsics.d(hArr);
            h = null;
            for (H h3 : hArr) {
                Intrinsics.d(h3);
                if (X(h3, hZ)) {
                    h = h3;
                }
            }
            if (h != null) {
                int spanStart2 = u().getSpanStart(h);
                if (u().getSpanEnd(h) > i) {
                    h.h(u(), i, i2);
                    return;
                }
                V(h, spanStart2, i2);
            }
        } else {
            h = null;
        }
        if (aztecText3.length() > i2) {
            H[] hArr2 = (H[]) u().getSpans(i2, i2 + 1, H.class);
            Intrinsics.d(hArr2);
            h2 = null;
            for (H h4 : hArr2) {
                Intrinsics.d(h4);
                if (X(h4, hZ)) {
                    h2 = h4;
                }
            }
            if (h2 != null) {
                int spanEnd2 = u().getSpanEnd(h2);
                V(h2, i, spanEnd2);
                u().setSpan(h2, i, spanEnd2, 33);
            }
        } else {
            h2 = null;
        }
        if (h == null && h2 == null) {
            H[] hArr3 = (H[]) u().getSpans(i, i2, H.class);
            Intrinsics.d(hArr3);
            H h5 = null;
            for (H h6 : hArr3) {
                Intrinsics.d(h6);
                if (X(h6, hZ)) {
                    h5 = h6;
                }
            }
            if (h5 != null) {
                u().removeSpan(h5);
                hZ.r(c5146b);
            }
            V(hZ, i, i2);
        }
        Y(i, i2);
    }

    public final void V(H h, int i, int i2) {
        if (i <= i2 && i >= 0 && i2 <= u().length()) {
            u().setSpan(h, i, i2, 33);
            h.h(u(), i, i2);
            return;
        }
        AztecText aztecText = (AztecText) this.b;
        aztecText.getExternalLogger();
        org.wordpress.android.util.a.c("InlineFormatter.applySpan - setSpan has end before start. Start:" + i + " End:" + i2);
        StringBuilder sb = new StringBuilder("Logging the whole content");
        sb.append(aztecText.q(aztecText.getText()));
        org.wordpress.android.util.a.c(sb.toString());
    }

    public final boolean W(int i, int i2, G textFormat) {
        int i3;
        Object obj;
        Object obj2;
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        H hZ = Z(textFormat);
        if (i <= i2) {
            if (i == i2) {
                int i4 = i - 1;
                if (i4 >= 0 && (i3 = i + 1) <= u().length()) {
                    Object[] spans = u().getSpans(i4, i, H.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    int length = spans.length;
                    int i5 = 0;
                    while (true) {
                        obj = null;
                        if (i5 >= length) {
                            obj2 = null;
                            break;
                        }
                        obj2 = spans[i5];
                        H h = (H) obj2;
                        Intrinsics.d(h);
                        if (X(h, hZ)) {
                            break;
                        }
                        i5++;
                    }
                    H h2 = (H) obj2;
                    Object[] spans2 = u().getSpans(i, i3, H.class);
                    Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                    int length2 = spans2.length;
                    int i6 = 0;
                    while (true) {
                        if (i6 >= length2) {
                            break;
                        }
                        Object obj3 = spans2[i6];
                        H h3 = (H) obj3;
                        Intrinsics.d(h3);
                        if (X(h3, hZ)) {
                            obj = obj3;
                            break;
                        }
                        i6++;
                    }
                    H h4 = (H) obj;
                    if (h2 != null && h4 != null && X(h2, h4)) {
                        return true;
                    }
                }
            } else {
                StringBuilder sb = new StringBuilder();
                int i7 = i;
                while (i7 < i2) {
                    int i8 = i7 + 1;
                    H[] hArr = (H[]) u().getSpans(i7, i8, H.class);
                    Intrinsics.d(hArr);
                    int length3 = hArr.length;
                    int i9 = 0;
                    while (true) {
                        if (i9 < length3) {
                            H h5 = hArr[i9];
                            Intrinsics.d(h5);
                            if (X(h5, hZ)) {
                                sb.append(u().subSequence(i7, i8).toString());
                                break;
                            }
                            i9++;
                        }
                    }
                    i7 = i8;
                }
                String strReplace = new Regex("\n").replace(u().subSequence(i, i2), "");
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                String strReplace2 = new Regex("\n").replace(string, "");
                if (strReplace.length() > 0 && strReplace.equals(strReplace2)) {
                    return true;
                }
            }
        }
        return false;
    }

    public final void Y(int i, int i2) {
        if (i > 1) {
            H[] hArr = (H[]) u().getSpans(i, i2, H.class);
            H[] hArr2 = (H[]) u().getSpans(i - 1, i, H.class);
            Intrinsics.d(hArr);
            for (H h : hArr) {
                int spanEnd = u().getSpanEnd(h);
                int spanStart = u().getSpanStart(h);
                if (spanEnd != -1 && spanStart != -1) {
                    Intrinsics.d(hArr2);
                    for (H h2 : hArr2) {
                        int spanStart2 = u().getSpanStart(h2);
                        Intrinsics.d(h);
                        Intrinsics.d(h2);
                        if (X(h, h2) && spanEnd >= spanStart2) {
                            u().removeSpan(h2);
                            V(h, spanStart2, spanEnd);
                        }
                    }
                }
            }
        }
        if (((AztecText) this.b).length() > i2) {
            H[] hArr3 = (H[]) u().getSpans(i, i2, H.class);
            H[] hArr4 = (H[]) u().getSpans(i2, i2 + 1, H.class);
            Intrinsics.d(hArr3);
            for (H h3 : hArr3) {
                int spanEnd2 = u().getSpanEnd(h3);
                int spanStart3 = u().getSpanStart(h3);
                if (spanEnd2 != -1 && spanStart3 != -1) {
                    Intrinsics.d(hArr4);
                    for (H h4 : hArr4) {
                        int spanEnd3 = u().getSpanEnd(h4);
                        Intrinsics.d(h3);
                        Intrinsics.d(h4);
                        if (X(h3, h4) && spanEnd3 >= spanStart3) {
                            u().removeSpan(h4);
                            V(h3, spanStart3, spanEnd3);
                        }
                    }
                }
            }
        }
        H[] hArr5 = (H[]) u().getSpans(i, i2, H.class);
        H[] hArr6 = (H[]) u().getSpans(i, i2, H.class);
        Intrinsics.d(hArr5);
        for (H h5 : hArr5) {
            int spanStart4 = u().getSpanStart(h5);
            int spanEnd4 = u().getSpanEnd(h5);
            Intrinsics.d(hArr6);
            H h6 = null;
            for (H h7 : hArr6) {
                int spanStart5 = u().getSpanStart(h7);
                int spanEnd5 = u().getSpanEnd(h7);
                Intrinsics.d(h7);
                Intrinsics.d(h5);
                if (X(h7, h5) && (spanStart5 == spanEnd4 || spanEnd5 == spanStart4)) {
                    h6 = h7;
                }
            }
            if (h6 != null) {
                int spanStart6 = u().getSpanStart(h6);
                int spanEnd6 = u().getSpanEnd(h6);
                if (spanStart6 != -1 && spanEnd6 != -1) {
                    if (spanStart4 == spanEnd6) {
                        Intrinsics.d(h5);
                        V(h5, spanStart6, spanEnd4);
                    } else if (spanEnd4 == spanStart6) {
                        Intrinsics.d(h5);
                        V(h5, spanStart4, spanEnd6);
                    }
                    u().removeSpan(h6);
                }
            }
        }
    }

    public final H Z(G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        if (textFormat == x.k) {
            return new AztecStyleBoldSpan();
        }
        if (textFormat == x.l) {
            return new AztecStyleStrongSpan(new C5146b());
        }
        if (textFormat == x.m) {
            return new AztecStyleItalicSpan();
        }
        if (textFormat == x.n) {
            return new AztecStyleEmphasisSpan(new C5146b());
        }
        if (textFormat == x.o) {
            return new AztecStyleCiteSpan(new C5146b());
        }
        if (textFormat == x.q) {
            return new AztecStrikethroughSpan("s", new C5146b());
        }
        if (textFormat == x.p) {
            return new AztecUnderlineSpan();
        }
        if (textFormat == x.F) {
            C5146b attributes = new C5146b();
            j codeStyle = this.c;
            Intrinsics.checkNotNullParameter(codeStyle, "codeStyle");
            Intrinsics.checkNotNullParameter(attributes, "attributes");
            C5154b c5154b = new C5154b(attributes);
            c5154b.c = codeStyle;
            return c5154b;
        }
        if (textFormat == x.G) {
            Integer num = this.e;
            return new AztecBackgroundColorSpan(num != null ? num.intValue() : R.color.background);
        }
        if (textFormat != x.I) {
            return textFormat == x.H ? new S(null, new C5146b()) : new AztecStyleSpan(0);
        }
        int i = HighlightSpan.c;
        Context context = ((AztecText) this.b).getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return C5174w.a(null, context, this.d, 1);
    }

    public final void a0() {
        Editable editableU = u();
        AztecText aztecText = (AztecText) this.b;
        Object[] spans = editableU.getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), F.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            F f = (F) obj;
            Intrinsics.d(f);
            d0(f, aztecText.getSelectionStart(), aztecText.getSelectionEnd());
        }
    }

    public final void b0(int i, int i2) {
        Object[] spans = u().getSpans(i, i2, ForegroundColorSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            u().removeSpan((ForegroundColorSpan) obj);
        }
        Object[] spans2 = u().getSpans(i, i2, BackgroundColorSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
        for (Object obj2 : spans2) {
            u().removeSpan((BackgroundColorSpan) obj2);
        }
    }

    public final void c0(int i, int i2, G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        d0(Z(textFormat), i, i2);
    }

    public final void d0(H spanToRemove, int i, int i2) {
        Intrinsics.checkNotNullParameter(spanToRemove, "spanToRemove");
        x xVarE0 = e0(spanToRemove);
        if (xVarE0 == null) {
            return;
        }
        H[] hArr = (H[]) u().getSpans(i, i2, H.class);
        ArrayList arrayList = new ArrayList();
        Intrinsics.d(hArr);
        for (H h : hArr) {
            Intrinsics.d(h);
            if (X(h, spanToRemove)) {
                arrayList.add(new C5149e(u().getSpanStart(h), u().getSpanEnd(h), h.f()));
                u().removeSpan(h);
            }
        }
        AztecText aztecText = (AztecText) this.b;
        b0(aztecText.getSelectionStart(), aztecText.getSelectionEnd());
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            C5149e c5149e = (C5149e) it2.next();
            int i3 = c5149e.a;
            int i4 = c5149e.b;
            if (i3 < i4) {
                C5146b c5146b = c5149e.c;
                if (i3 < i) {
                    T(xVarE0, i3, i, c5146b);
                }
                if (i4 > i2) {
                    T(xVarE0, i2, i4, c5146b);
                }
            }
        }
        Y(i, i2);
    }

    public final void f0(G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        AztecText aztecText = (AztecText) this.b;
        if (W(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), textFormat)) {
            c0(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), textFormat);
            return;
        }
        if (Z(textFormat) instanceof F) {
            Object[] spans = u().getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), H.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            ArrayList arrayList = new ArrayList();
            for (Object obj : spans) {
                if (!(((H) obj) instanceof F)) {
                    arrayList.add(obj);
                }
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                H h = (H) it2.next();
                Intrinsics.d(h);
                d0(h, aztecText.getSelectionStart(), aztecText.getSelectionEnd());
            }
        } else {
            a0();
        }
        U(this, textFormat, 0, 0, 14);
    }
}
