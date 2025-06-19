package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.Spannable;
import android.text.Spanned;
import android.text.TextWatcher;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.O;
import org.wordpress.aztec.spans.P;

/* loaded from: classes3.dex */
public final class d implements TextWatcher {
    public final /* synthetic */ int a;
    public final WeakReference b;

    public d(AztecText aztecText, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new WeakReference(aztecText);
                break;
            case 2:
                this.b = new WeakReference(aztecText);
                break;
            default:
                this.b = new WeakReference(aztecText);
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "text");
                WeakReference weakReference = this.b;
                AztecText aztecText = (AztecText) weakReference.get();
                if (!(aztecText != null ? aztecText.m : true)) {
                    Object[] spans = s.getSpans(0, s.length(), P.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    for (Object obj : spans) {
                        P p = (P) obj;
                        int spanStart = s.getSpanStart(p);
                        int spanEnd = s.getSpanEnd(p);
                        if (spanStart > -1 && spanEnd > -1) {
                            AztecText aztecText2 = (AztecText) weakReference.get();
                            if (aztecText2 != null) {
                                aztecText2.m = true;
                            }
                            s.delete(spanStart, spanEnd);
                            AztecText aztecText3 = (AztecText) weakReference.get();
                            if (aztecText3 != null) {
                                aztecText3.m = false;
                            }
                        }
                    }
                    break;
                }
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        int i4;
        O[] spanObjects;
        Spanned spanned;
        int i5;
        int i6;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                AztecText aztecText = (AztecText) this.b.get();
                if (!(aztecText != null ? aztecText.m : true) && i != 0 && i2 != 0 && i + i2 >= s.length()) {
                    int i7 = i - 1;
                    if (s.charAt(i7) == '\n') {
                        CharSequence charSequenceSubSequence = s.subSequence(i7, i);
                        Intrinsics.e(charSequenceSubSequence, "null cannot be cast to non-null type android.text.Spanned");
                        Spannable spannable = (Spannable) s;
                        Object[] spanObjects2 = ((Spanned) charSequenceSubSequence).getSpans(0, 1, O.class);
                        Intrinsics.checkNotNullExpressionValue(spanObjects2, "getSpans(...)");
                        Intrinsics.checkNotNullParameter(spannable, "spannable");
                        Intrinsics.checkNotNullParameter(spanObjects2, "spanObjects");
                        ArrayList arrayList = new ArrayList(spanObjects2.length);
                        for (Object obj : spanObjects2) {
                            arrayList.add(new org.wordpress.aztec.util.d(spannable, obj));
                        }
                        ArrayList arrayList2 = new ArrayList();
                        Iterator it2 = arrayList.iterator();
                        while (it2.hasNext()) {
                            Object next = it2.next();
                            org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) next;
                            if (dVar.b() < i && dVar.a() == i) {
                                arrayList2.add(next);
                            }
                        }
                        Iterator it3 = arrayList2.iterator();
                        while (it3.hasNext()) {
                            ((O) ((org.wordpress.aztec.util.d) it3.next()).b).p(i);
                        }
                        break;
                    }
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(s, "s");
                AztecText aztecText2 = (AztecText) this.b.get();
                if (!(aztecText2 != null ? aztecText2.m : true)) {
                    int i8 = i + i2;
                    CharSequence charSequenceSubSequence2 = s.subSequence(i, i8);
                    Intrinsics.e(charSequenceSubSequence2, "null cannot be cast to non-null type android.text.Spanned");
                    Spanned spanned2 = (Spanned) charSequenceSubSequence2;
                    Spannable spannable2 = (Spannable) s;
                    Intrinsics.checkNotNullParameter(spannable2, "spannable");
                    Intrinsics.checkNotNullParameter(O.class, DBUserFields.Names.USER_UPGRADE_TYPE);
                    Object[] spanObjects3 = spannable2.getSpans(i, i8, O.class);
                    Intrinsics.checkNotNullExpressionValue(spanObjects3, "getSpans(...)");
                    Intrinsics.checkNotNullParameter(spannable2, "spannable");
                    Intrinsics.checkNotNullParameter(spanObjects3, "spanObjects");
                    ArrayList arrayList3 = new ArrayList(spanObjects3.length);
                    int i9 = 1;
                    for (Object obj2 : spanObjects3) {
                        arrayList3.add(new org.wordpress.aztec.util.d(spannable2, obj2));
                    }
                    if (!arrayList3.isEmpty() || i8 < s.length()) {
                        char c = '\n';
                        int i10 = 4;
                        int iL = StringsKt.L(s.toString(), '\n', i8, false, 4);
                        int i11 = -1;
                        if (iL == -1) {
                            iL = s.length();
                        }
                        String string = spanned2.toString();
                        int length = string.length();
                        while (true) {
                            length = StringsKt.P(string, c, length - 1, i10);
                            if (length == i11) {
                                break;
                            } else {
                                int i12 = i + length;
                                int i13 = i12 + 2;
                                if (i13 > s.length()) {
                                    i5 = i9;
                                    i4 = iL;
                                    i6 = i11;
                                    spanned = spanned2;
                                } else {
                                    int i14 = i12 + 1;
                                    if (i14 < s.length()) {
                                        CharSequence charSequenceSubSequence3 = s.subSequence(i14, i13);
                                        Intrinsics.e(charSequenceSubSequence3, "null cannot be cast to non-null type android.text.Spanned");
                                        i4 = iL;
                                        Object[] spans = ((Spanned) charSequenceSubSequence3).getSpans(0, i9, O.class);
                                        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                                        spanObjects = (O[]) spans;
                                    } else {
                                        i4 = iL;
                                        int i15 = length + 1;
                                        Object[] spans2 = spanned2.getSpans(i15, i15, O.class);
                                        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                                        spanObjects = (O[]) spans2;
                                    }
                                    Intrinsics.checkNotNullParameter(spannable2, "spannable");
                                    Intrinsics.checkNotNullParameter(spanObjects, "spanObjects");
                                    ArrayList arrayList4 = new ArrayList(spanObjects.length);
                                    int length2 = spanObjects.length;
                                    O[] oArr = spanObjects;
                                    int i16 = 0;
                                    while (i16 < length2) {
                                        int i17 = i16;
                                        arrayList4.add(new org.wordpress.aztec.util.d(spannable2, oArr[i17]));
                                        i16 = i17 + 1;
                                        spanned2 = spanned2;
                                    }
                                    spanned = spanned2;
                                    ArrayList arrayList5 = new ArrayList();
                                    Iterator it4 = arrayList4.iterator();
                                    while (it4.hasNext()) {
                                        Object next2 = it4.next();
                                        if (((org.wordpress.aztec.util.d) next2).b() == i14) {
                                            arrayList5.add(next2);
                                        }
                                    }
                                    Iterator it5 = arrayList5.iterator();
                                    while (it5.hasNext()) {
                                        org.wordpress.aztec.util.d dVar2 = (org.wordpress.aztec.util.d) it5.next();
                                        if (dVar2.a() <= i4 + 1) {
                                            dVar2.c();
                                        }
                                    }
                                    i5 = 1;
                                    i6 = -1;
                                }
                                if (length <= i6) {
                                    break;
                                } else {
                                    i11 = i6;
                                    i9 = i5;
                                    iL = i4;
                                    spanned2 = spanned;
                                    c = '\n';
                                    i10 = 4;
                                }
                            }
                        }
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                AztecText aztecText = (AztecText) this.b.get();
                if (!(aztecText != null ? aztecText.m : true) && i3 != 0) {
                    Spannable spannable = (Spannable) s;
                    Intrinsics.checkNotNullParameter(spannable, "spannable");
                    Intrinsics.checkNotNullParameter(O.class, DBUserFields.Names.USER_UPGRADE_TYPE);
                    Object[] spanObjects = spannable.getSpans(i, i, O.class);
                    Intrinsics.checkNotNullExpressionValue(spanObjects, "getSpans(...)");
                    Intrinsics.checkNotNullParameter(spannable, "spannable");
                    Intrinsics.checkNotNullParameter(spanObjects, "spanObjects");
                    ArrayList arrayList = new ArrayList(spanObjects.length);
                    for (Object obj : spanObjects) {
                        arrayList.add(new org.wordpress.aztec.util.d(spannable, obj));
                    }
                    ArrayList arrayList2 = new ArrayList();
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        Object next = it2.next();
                        if (((O) ((org.wordpress.aztec.util.d) next).b).m()) {
                            arrayList2.add(next);
                        }
                    }
                    Iterator it3 = arrayList2.iterator();
                    while (it3.hasNext()) {
                        org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) it3.next();
                        dVar.d(((O) dVar.b).i());
                        ((O) dVar.b).q();
                    }
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
        }
    }
}
