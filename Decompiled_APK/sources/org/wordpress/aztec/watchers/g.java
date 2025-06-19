package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.Spannable;
import android.text.TextWatcher;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.H;

/* loaded from: classes3.dex */
public final class g implements TextWatcher {
    public final WeakReference a;
    public h b;
    public final ArrayList c;
    public boolean d;
    public boolean e;
    public boolean f;
    public boolean g;
    public int h;
    public int i;

    public g(AztecText aztecText) {
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.a = new WeakReference(aztecText);
        this.b = new h();
        this.c = new ArrayList();
        this.h = -1;
        this.i = -1;
    }

    public final void a(Spannable spannable, int i, int i2, int i3) {
        int i4 = i3 - i2;
        ArrayList arrayList = this.c;
        if (i4 >= 0 && i2 > 0) {
            Object[] spans = spannable.getSpans(i, i2 + i, H.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (Object obj : spans) {
                H h = (H) obj;
                int spanStart = spannable.getSpanStart(h);
                int spanEnd = spannable.getSpanEnd(h);
                Intrinsics.d(h);
                arrayList.add(new f(h, spanStart, spanEnd));
            }
            return;
        }
        if (i4 >= 0 || i2 <= 0) {
            return;
        }
        int i5 = i2 - i3;
        if (i5 > 1) {
            int i6 = i + i2;
            Object[] spans2 = spannable.getSpans(i, i6, H.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            for (Object obj2 : spans2) {
                H h2 = (H) obj2;
                boolean z = i2 == 2 && spannable.charAt(i) == ' ' && spannable.charAt(i + 1) == ' ';
                int spanStart2 = spannable.getSpanStart(h2);
                int spanEnd2 = (spannable.getSpanEnd(h2) < i6 || z) ? spannable.getSpanEnd(h2) : spannable.getSpanEnd(h2) - i5;
                Intrinsics.d(h2);
                arrayList.add(new f(h2, spanStart2, spanEnd2));
            }
            return;
        }
        int i7 = i + i3;
        Object[] spans3 = spannable.getSpans(i, i7, H.class);
        Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
        for (Object obj3 : spans3) {
            H h3 = (H) obj3;
            int spanStart3 = spannable.getSpanStart(h3);
            int spanEnd3 = spannable.getSpanEnd(h3);
            if ((i != spanEnd3 || spannable.charAt(i) != ' ') && i7 < spanEnd3 && i < spanEnd3 && i5 == 1) {
                spanEnd3--;
            }
            Intrinsics.d(h3);
            arrayList.add(new f(h3, spanStart3, spanEnd3));
        }
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        WeakReference weakReference = this.a;
        AztecText aztecText = (AztecText) weakReference.get();
        if (aztecText == null || aztecText.m) {
            return;
        }
        if (this.d) {
            this.d = false;
            AztecText aztecText2 = (AztecText) weakReference.get();
            if (aztecText2 != null) {
                aztecText2.n = false;
            }
            AztecText aztecText3 = (AztecText) weakReference.get();
            if (aztecText3 != null) {
                aztecText3.o = false;
            }
        }
        this.f = this.e;
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
        WeakReference weakReference = this.a;
        AztecText aztecText = (AztecText) weakReference.get();
        if (aztecText == null || aztecText.m || !(text instanceof Spannable)) {
            return;
        }
        this.b = new h(text.toString(), 6);
        AztecText aztecText2 = (AztecText) weakReference.get();
        Integer numValueOf = aztecText2 != null ? Integer.valueOf(aztecText2.getSelectionStart()) : null;
        AztecText aztecText3 = (AztecText) weakReference.get();
        boolean zB = Intrinsics.b(numValueOf, aztecText3 != null ? Integer.valueOf(aztecText3.getSelectionEnd()) : null);
        boolean z = (numValueOf == null || numValueOf.intValue() != i + 1) && i3 == 0 && zB && i2 > 1;
        this.e = z;
        boolean z2 = this.h == i && this.i == i3 && this.f;
        this.d = z2;
        if (!z && !z2 && zB) {
            AztecText aztecText4 = (AztecText) weakReference.get();
            if (aztecText4 != null) {
                aztecText4.n = false;
            }
            this.c.clear();
            a((Spannable) text, i, i2, i3);
            this.g = true;
        } else if (z && this.g) {
            AztecText aztecText5 = (AztecText) weakReference.get();
            if (aztecText5 != null) {
                aztecText5.n = true;
            }
            a((Spannable) text, i, i2, i3);
            this.g = false;
        } else if (z2) {
            AztecText aztecText6 = (AztecText) weakReference.get();
            if (aztecText6 != null) {
                aztecText6.o = false;
            }
            this.g = false;
        }
        this.h = i;
        this.i = i2;
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        int i4;
        Intrinsics.checkNotNullParameter(text, "text");
        AztecText aztecText = (AztecText) this.a.get();
        if (aztecText == null || aztecText.m || !(text instanceof Spannable)) {
            return;
        }
        h hVar = this.b;
        hVar.d = i2;
        Intrinsics.checkNotNullParameter(text, "<set-?>");
        hVar.c = text;
        h hVar2 = this.b;
        hVar2.f = i3;
        hVar2.e = i;
        hVar2.a();
        boolean z = this.e;
        ArrayList arrayList = this.c;
        if (!z && arrayList.size() > 0) {
            Spannable spannable = (Spannable) text;
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                f fVar = (f) it2.next();
                if (fVar.b >= 0) {
                    int length = spannable.length();
                    int i5 = fVar.c;
                    if (i5 <= length && (i4 = fVar.b) < i5) {
                        try {
                            spannable.setSpan(fVar.a, i4, i5, 33);
                        } catch (IndexOutOfBoundsException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        if (this.d) {
            arrayList.clear();
        }
    }
}
