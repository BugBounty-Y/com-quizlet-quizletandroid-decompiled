package org.wordpress.aztec.formatting;

import android.content.Context;
import android.text.Editable;
import android.text.Layout;
import android.text.TextUtils;
import androidx.compose.animation.core.J0;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.E2;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.P2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import com.google.android.gms.internal.mlkit_vision_camera.X2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.K;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.G;
import org.wordpress.aztec.spans.AztecListSpan;
import org.wordpress.aztec.spans.AztecOrderedListSpan;
import org.wordpress.aztec.spans.AztecPreformatSpan;
import org.wordpress.aztec.spans.AztecTaskListSpan;
import org.wordpress.aztec.spans.AztecUnorderedListSpan;
import org.wordpress.aztec.spans.B;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5168p;
import org.wordpress.aztec.spans.C5174w;
import org.wordpress.aztec.spans.D;
import org.wordpress.aztec.spans.E;
import org.wordpress.aztec.spans.EnumC5157e;
import org.wordpress.aztec.spans.T;
import org.wordpress.aztec.x;

/* loaded from: classes3.dex */
public final class i extends J0 {
    public final e c;
    public final d d;
    public final h e;
    public final c f;
    public final g g;
    public final EnumC5145a h;
    public final a i;
    public final f j;
    public final Set k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(AztecText editor, e listStyle, d listItemStyle, h quoteStyle, c headerStyle, g preformatStyle, EnumC5145a alignmentRendering, a exclusiveBlockStyles, f paragraphStyle) {
        super(editor);
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        Intrinsics.checkNotNullParameter(quoteStyle, "quoteStyle");
        Intrinsics.checkNotNullParameter(headerStyle, "headerStyle");
        Intrinsics.checkNotNullParameter(preformatStyle, "preformatStyle");
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(exclusiveBlockStyles, "exclusiveBlockStyles");
        Intrinsics.checkNotNullParameter(paragraphStyle, "paragraphStyle");
        this.c = listStyle;
        this.d = listItemStyle;
        this.e = quoteStyle;
        this.f = headerStyle;
        this.g = preformatStyle;
        this.h = alignmentRendering;
        this.i = exclusiveBlockStyles;
        this.j = paragraphStyle;
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(editor, "editor");
        x[] elements = {x.j, x.i, x.h};
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.k = C4933y.T(elements);
    }

    /* JADX WARN: Removed duplicated region for block: B:147:0x045a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void U(org.wordpress.aztec.formatting.i r26, org.wordpress.aztec.G r27) {
        /*
            Method dump skipped, instructions count: 1201
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.formatting.i.U(org.wordpress.aztec.formatting.i, org.wordpress.aztec.G):void");
    }

    public static int X(HashMap map, int i, ArrayList arrayList, int i2) {
        Object obj = map.get(Integer.valueOf(i));
        Intrinsics.d(obj);
        int iIntValue = ((Number) obj).intValue();
        Object obj2 = map.get(Integer.valueOf(i2));
        Intrinsics.d(obj2);
        if (iIntValue == ((Number) obj2).intValue()) {
            return -1;
        }
        Object obj3 = map.get(Integer.valueOf(i));
        Intrinsics.d(obj3);
        int iIntValue2 = ((Number) obj3).intValue();
        Object obj4 = map.get(Integer.valueOf(i2));
        Intrinsics.d(obj4);
        if (iIntValue2 >= ((Number) obj4).intValue()) {
            return -1;
        }
        arrayList.add(Integer.valueOf(i));
        return i;
    }

    public static boolean a0(i iVar, x xVar) {
        return iVar.Z(((AztecText) iVar.b).getSelectionStart(), ((AztecText) iVar.b).getSelectionEnd(), xVar);
    }

    public static boolean b0(i iVar, G textFormat) {
        AztecText aztecText = (AztecText) iVar.b;
        int selectionStart = aztecText.getSelectionStart();
        int selectionEnd = aztecText.getSelectionEnd();
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        x[] xVarArr = {x.b, x.c, x.d, x.e, x.f, x.g, x.y};
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < 7; i++) {
            x xVar = xVarArr[i];
            if (xVar != textFormat) {
                arrayList.add(xVar);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (iVar.Y(selectionStart, selectionEnd, (x) it2.next())) {
                return true;
            }
        }
        return false;
    }

    public static Layout.Alignment f0(G g, CharSequence text) {
        Intrinsics.checkNotNullParameter(text, "text");
        boolean zT = androidx.core.text.f.c.t(text, 0, text.length());
        if (g == x.r) {
            return !zT ? Layout.Alignment.ALIGN_NORMAL : Layout.Alignment.ALIGN_OPPOSITE;
        }
        if (g == x.s) {
            return Layout.Alignment.ALIGN_CENTER;
        }
        if (g == x.t) {
            return zT ? Layout.Alignment.ALIGN_NORMAL : Layout.Alignment.ALIGN_OPPOSITE;
        }
        return null;
    }

    public static /* synthetic */ List k0(i iVar, G g) {
        return iVar.j0(g, 0, new C5146b());
    }

    public static /* synthetic */ D n0(i iVar, G g, int i) {
        return iVar.m0(g, i, new C5146b());
    }

    public static void s0(i iVar, x xVar) {
        AztecListSpan aztecListSpan;
        AztecText aztecText;
        Iterator it2;
        Object[] objArr;
        int selectionStart = ((AztecText) iVar.b).getSelectionStart();
        int selectionEnd = ((AztecText) iVar.b).getSelectionEnd();
        C5146b c5146b = new C5146b();
        AztecListSpan[] aztecListSpanArr = (AztecListSpan[]) iVar.u().getSpans(selectionStart, selectionEnd, AztecListSpan.class);
        Intrinsics.d(aztecListSpanArr);
        int i = 1;
        Object next = null;
        int i2 = 0;
        if (aztecListSpanArr.length == 0) {
            aztecListSpan = null;
        } else {
            aztecListSpan = aztecListSpanArr[0];
            Intrinsics.checkNotNullParameter(aztecListSpanArr, "<this>");
            int length = aztecListSpanArr.length - 1;
            if (length != 0) {
                int iA = aztecListSpan.a();
                kotlin.ranges.i it3 = new IntRange(1, length, 1).iterator();
                while (it3.c) {
                    AztecListSpan aztecListSpan2 = aztecListSpanArr[it3.nextInt()];
                    int iA2 = aztecListSpan2.a();
                    if (iA < iA2) {
                        aztecListSpan = aztecListSpan2;
                        iA = iA2;
                    }
                }
            }
        }
        Integer numValueOf = aztecListSpan != null ? Integer.valueOf(aztecListSpan.a()) : null;
        if (selectionStart == selectionEnd) {
            ArrayList arrayList = new ArrayList();
            for (AztecListSpan aztecListSpan3 : aztecListSpanArr) {
                int iA3 = aztecListSpan3.a();
                if (numValueOf != null && iA3 == numValueOf.intValue()) {
                    arrayList.add(aztecListSpan3);
                }
            }
            if (arrayList.size() > 1) {
                ArrayList arrayList2 = new ArrayList();
                for (AztecListSpan aztecListSpan4 : aztecListSpanArr) {
                    if (iVar.u().getSpanStart(aztecListSpan4) == selectionStart) {
                        arrayList2.add(aztecListSpan4);
                    }
                }
                aztecListSpanArr = (AztecListSpan[]) arrayList2.toArray(new AztecListSpan[0]);
            }
        }
        Intrinsics.d(aztecListSpanArr);
        ArrayList arrayList3 = new ArrayList(aztecListSpanArr.length);
        for (AztecListSpan aztecListSpan5 : aztecListSpanArr) {
            arrayList3.add(Integer.valueOf(iVar.u().getSpanStart(aztecListSpan5)));
        }
        ArrayList arrayList4 = new ArrayList();
        Iterator it4 = arrayList3.iterator();
        while (true) {
            boolean zHasNext = it4.hasNext();
            aztecText = (AztecText) iVar.b;
            if (!zHasNext) {
                break;
            }
            Object next2 = it4.next();
            if (((Number) next2).intValue() <= aztecText.getSelectionStart()) {
                arrayList4.add(next2);
            }
        }
        Iterator it5 = arrayList4.iterator();
        if (it5.hasNext()) {
            next = it5.next();
            if (it5.hasNext()) {
                int iIntValue = ((Number) next).intValue();
                do {
                    Object next3 = it5.next();
                    int iIntValue2 = ((Number) next3).intValue();
                    if (iIntValue < iIntValue2) {
                        next = next3;
                        iIntValue = iIntValue2;
                    }
                } while (it5.hasNext());
            }
        }
        Integer num = (Integer) next;
        int iIntValue3 = num != null ? num.intValue() : aztecText.getSelectionStart();
        ArrayList arrayList5 = new ArrayList();
        for (AztecListSpan aztecListSpan6 : aztecListSpanArr) {
            if (iVar.u().getSpanStart(aztecListSpan6) >= iIntValue3) {
                arrayList5.add(aztecListSpan6);
            }
        }
        Iterator it6 = arrayList5.iterator();
        while (it6.hasNext()) {
            AztecListSpan aztecListSpan7 = (AztecListSpan) it6.next();
            if (aztecListSpan7 != null) {
                int spanStart = iVar.u().getSpanStart(aztecListSpan7);
                int spanEnd = iVar.u().getSpanEnd(aztecListSpan7);
                int spanFlags = iVar.u().getSpanFlags(aztecListSpan7);
                iVar.u().removeSpan(aztecListSpan7);
                boolean z = aztecListSpan7 instanceof AztecTaskListSpan;
                int i3 = xVar == x.j ? i : i2;
                Object[] spans = iVar.u().getSpans(spanStart, spanEnd, C5164l.class);
                Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                int length2 = spans.length;
                while (i2 < length2) {
                    Iterator it7 = it6;
                    C5164l c5164l = (C5164l) spans[i2];
                    AztecListSpan aztecListSpan8 = aztecListSpan7;
                    if (z) {
                        c5164l.b.c("checked");
                    } else {
                        if (i3 != 0) {
                            objArr = spans;
                            c5164l.b.d("checked", "false");
                        }
                        i2++;
                        aztecListSpan7 = aztecListSpan8;
                        it6 = it7;
                        spans = objArr;
                    }
                    objArr = spans;
                    i2++;
                    aztecListSpan7 = aztecListSpan8;
                    it6 = it7;
                    spans = objArr;
                }
                it2 = it6;
                iVar.u().setSpan(iVar.m0(xVar, aztecListSpan7.a(), c5146b), spanStart, spanEnd, spanFlags);
                aztecText.onSelectionChanged(selectionStart, selectionEnd);
            } else {
                it2 = it6;
            }
            it6 = it2;
            i = 1;
            i2 = 0;
        }
    }

    public final void T(D d, int i, int i2) {
        if (d instanceof AztecOrderedListSpan) {
            V((AztecListSpan) d, i, i2);
            return;
        }
        if (d instanceof AztecUnorderedListSpan) {
            V((AztecListSpan) d, i, i2);
            return;
        }
        if (d instanceof AztecTaskListSpan) {
            V((AztecListSpan) d, i, i2);
            return;
        }
        if (d instanceof C5168p) {
            E2.b(u(), (C5168p) d, i, i2);
            return;
        }
        if (!(d instanceof C5160h)) {
            if (d instanceof AztecPreformatSpan) {
                E2.b(u(), d, i, i2);
                return;
            } else {
                u().setSpan(d, i, i2, 51);
                return;
            }
        }
        C5160h block = (C5160h) d;
        String[] strArrSplit = TextUtils.split(u().subSequence(i, i2).toString(), "\n");
        int length = strArrSplit.length;
        for (int i3 = 0; i3 < length; i3++) {
            int length2 = strArrSplit[i3].length();
            kotlin.ranges.i it2 = kotlin.ranges.l.h(0, i3).iterator();
            int length3 = 0;
            while (it2.c) {
                length3 += strArrSplit[it2.nextInt()].length() + 1;
            }
            int i4 = length3 + i;
            int i5 = length2 + i4 + 1;
            if (i5 > i2) {
                i5 = i2;
            }
            if (i5 - i4 != 0) {
                Editable text = u();
                Intrinsics.checkNotNullParameter(text, "text");
                Intrinsics.checkNotNullParameter(block, "block");
                EnumC5145a alignmentRendering = this.h;
                Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
                E2.b(text, M2.d(block.a(), block.f, block.f(), alignmentRendering, block.e()), i4, i5);
            }
        }
    }

    public final void V(AztecListSpan aztecListSpan, int i, int i2) {
        boolean z;
        int i3 = i;
        int i4 = i2;
        E2.b(u(), aztecListSpan, i3, i4);
        int i5 = i4 - i3;
        d listItemStyle = this.d;
        EnumC5145a alignmentRendering = this.h;
        if (i5 == 1) {
            z = true;
            int i6 = i4 - 1;
            if (u().charAt(i6) == '\n' || u().charAt(i6) == C2.i) {
                Editable text = u();
                int iA = aztecListSpan.a() + 1;
                Intrinsics.checkNotNullParameter(text, "text");
                Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
                Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
                Object[] spans = text.getSpans(i3, i4, AztecTaskListSpan.class);
                boolean z2 = spans == null || spans.length == 0;
                C5164l c5164lB = N2.b(iA, alignmentRendering, null, listItemStyle, 4);
                if (!z2) {
                    c5164lB.b.d("checked", "false");
                }
                Unit unit = Unit.a;
                E2.b(text, c5164lB, i3, i4);
                return;
            }
        } else {
            z = true;
        }
        if (i4 != u().length()) {
            i4--;
        }
        String[] strArrSplit = TextUtils.split(u().subSequence(i3, i4).toString(), "\n");
        int length = strArrSplit.length;
        int i7 = 0;
        while (i7 < length) {
            int length2 = strArrSplit[i7].length();
            kotlin.ranges.i it2 = kotlin.ranges.l.h(0, i7).iterator();
            int length3 = 0;
            while (it2.c) {
                length3 = strArrSplit[it2.nextInt()].length() + 1 + length3;
            }
            int i8 = length3 + length2;
            if (i3 + i8 != u().length()) {
                i8++;
            }
            Editable text2 = u();
            int i9 = i3 + length3;
            int i10 = i8 + i3;
            int iA2 = aztecListSpan.a() + 1;
            Intrinsics.checkNotNullParameter(text2, "text");
            Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
            Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
            String[] strArr = strArrSplit;
            Object[] spans2 = text2.getSpans(i9, i10, AztecTaskListSpan.class);
            boolean z3 = (spans2 == null || spans2.length == 0) ? z : false;
            int i11 = length;
            C5164l c5164lB2 = N2.b(iA2, alignmentRendering, null, listItemStyle, 4);
            if (!z3) {
                c5164lB2.b.d("checked", "false");
            }
            Unit unit2 = Unit.a;
            E2.b(text2, c5164lB2, i9, i10);
            i7++;
            i3 = i;
            strArrSplit = strArr;
            length = i11;
        }
    }

    public final void W(B b, G g) {
        Editable spannable = u();
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        b.c(f0(g, StringsKt.Y(u(), kotlin.ranges.l.h(spannable.getSpanStart(b), spannable.getSpanEnd(b)))));
        u().setSpan(b, spannable.getSpanStart(b), spannable.getSpanEnd(b), spannable.getSpanFlags(b));
    }

    public final boolean Y(int i, int i2, G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        String[] strArrSplit = TextUtils.split(u().toString(), "\n");
        ArrayList arrayList = new ArrayList();
        int length = strArrSplit.length;
        for (int i3 = 0; i3 < length; i3++) {
            kotlin.ranges.i it2 = kotlin.ranges.l.h(0, i3).iterator();
            int length2 = 0;
            while (it2.c) {
                length2 += strArrSplit[it2.nextInt()].length() + 1;
            }
            int length3 = strArrSplit[i3].length() + length2;
            if (length2 < length3 && ((length2 >= i && i2 >= length3) || ((length2 <= i2 && i2 <= length3) || (length2 <= i && i <= length3)))) {
                arrayList.add(Integer.valueOf(i3));
            }
        }
        if (!arrayList.isEmpty() && !arrayList.isEmpty()) {
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                int iIntValue = ((Number) it3.next()).intValue();
                String[] strArrSplit2 = TextUtils.split(u().toString(), "\n");
                if (iIntValue >= 0 && iIntValue < strArrSplit2.length) {
                    kotlin.ranges.i it4 = kotlin.ranges.l.h(0, iIntValue).iterator();
                    int length4 = 0;
                    while (it4.c) {
                        length4 += strArrSplit2[it4.nextInt()].length() + 1;
                    }
                    int length5 = strArrSplit2[iIntValue].length() + length4;
                    if (length4 >= length5) {
                        continue;
                    } else {
                        C5160h[] c5160hArr = (C5160h[]) u().getSpans(length4, length5, C5160h.class);
                        Intrinsics.d(c5160hArr);
                        if (c5160hArr.length > 0) {
                            C5160h c5160h = c5160hArr[0];
                            if (textFormat == x.b) {
                                if (c5160h.k() == EnumC5157e.c) {
                                    return true;
                                }
                            } else if (textFormat == x.c) {
                                if (c5160h.k() == EnumC5157e.d) {
                                    return true;
                                }
                            } else if (textFormat == x.d) {
                                if (c5160h.k() == EnumC5157e.e) {
                                    return true;
                                }
                            } else if (textFormat == x.e) {
                                if (c5160h.k() == EnumC5157e.f) {
                                    return true;
                                }
                            } else if (textFormat == x.f) {
                                if (c5160h.k() == EnumC5157e.g) {
                                    return true;
                                }
                            } else if (textFormat == x.g && c5160h.k() == EnumC5157e.h) {
                                return true;
                            }
                        } else {
                            continue;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final boolean Z(int i, int i2, G format) {
        Iterable iterableP;
        Object next;
        Intrinsics.checkNotNullParameter(format, "format");
        String[] strArrSplit = TextUtils.split(u().toString(), "\n");
        ArrayList arrayList = new ArrayList();
        int length = strArrSplit.length;
        for (int i3 = 0; i3 < length; i3++) {
            kotlin.ranges.i it2 = kotlin.ranges.l.h(0, i3).iterator();
            int length2 = 0;
            while (it2.c) {
                length2 += strArrSplit[it2.nextInt()].length() + 1;
            }
            int length3 = strArrSplit[i3].length() + length2;
            if (length2 <= length3 && ((length2 >= i && i2 >= length3) || ((length2 <= i2 && i2 <= length3) || (length2 <= i && i <= length3)))) {
                arrayList.add(Integer.valueOf(i3));
            }
        }
        if (!arrayList.isEmpty() && !arrayList.isEmpty()) {
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                int iIntValue = ((Number) it3.next()).intValue();
                String[] strArrSplit2 = TextUtils.split(u().toString(), "\n");
                if (iIntValue < 0 || iIntValue >= strArrSplit2.length) {
                    iterableP = K.a;
                } else {
                    kotlin.ranges.i it4 = kotlin.ranges.l.h(0, iIntValue).iterator();
                    int length4 = 0;
                    while (it4.c) {
                        length4 += strArrSplit2[it4.nextInt()].length() + 1;
                    }
                    int length5 = strArrSplit2[iIntValue].length() + length4;
                    if (length4 > length5) {
                        iterableP = K.a;
                    } else {
                        Object[] spans = u().getSpans(length4, length5, AztecListSpan.class);
                        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                        iterableP = C4933y.P(spans);
                    }
                }
                Iterator it5 = iterableP.iterator();
                if (it5.hasNext()) {
                    next = it5.next();
                    if (it5.hasNext()) {
                        int iA = ((AztecListSpan) next).a();
                        do {
                            Object next2 = it5.next();
                            int iA2 = ((AztecListSpan) next2).a();
                            if (iA < iA2) {
                                next = next2;
                                iA = iA2;
                            }
                        } while (it5.hasNext());
                    }
                } else {
                    next = null;
                }
                AztecListSpan aztecListSpan = (AztecListSpan) next;
                Integer numValueOf = aztecListSpan != null ? Integer.valueOf(aztecListSpan.a()) : null;
                ArrayList arrayList2 = new ArrayList();
                for (Object obj : iterableP) {
                    int iA3 = ((AztecListSpan) obj).a();
                    if (numValueOf != null && iA3 == numValueOf.intValue()) {
                        arrayList2.add(obj);
                    }
                }
                if (!arrayList2.isEmpty()) {
                    Iterator it6 = arrayList2.iterator();
                    while (it6.hasNext()) {
                        AztecListSpan aztecListSpan2 = (AztecListSpan) it6.next();
                        if (aztecListSpan2 instanceof AztecUnorderedListSpan) {
                            if (format == x.h) {
                                return true;
                            }
                        } else if (aztecListSpan2 instanceof AztecOrderedListSpan) {
                            if (format == x.i) {
                                return true;
                            }
                        } else if ((aztecListSpan2 instanceof AztecTaskListSpan) && format == x.j) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final boolean c0() {
        String[] strArrSplit = TextUtils.split(u().toString(), "\n");
        ArrayList arrayList = new ArrayList();
        int length = strArrSplit.length;
        for (int i = 0; i < length; i++) {
            kotlin.ranges.i it2 = kotlin.ranges.l.h(0, i).iterator();
            int length2 = 0;
            while (it2.c) {
                length2 += strArrSplit[it2.nextInt()].length() + 1;
            }
            int length3 = strArrSplit[i].length() + length2;
            if (length2 <= length3) {
                AztecText aztecText = (AztecText) this.b;
                if (length2 <= aztecText.getSelectionEnd() && length3 >= aztecText.getSelectionStart()) {
                    arrayList.add(Integer.valueOf(i));
                }
            }
        }
        if (!arrayList.isEmpty() && !arrayList.isEmpty()) {
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                int iIntValue = ((Number) it3.next()).intValue();
                String[] strArrSplit2 = TextUtils.split(u().toString(), "\n");
                if (iIntValue >= 0 && iIntValue < strArrSplit2.length) {
                    kotlin.ranges.i it4 = kotlin.ranges.l.h(0, iIntValue).iterator();
                    int length4 = 0;
                    while (it4.c) {
                        length4 += strArrSplit2[it4.nextInt()].length() + 1;
                    }
                    int length5 = strArrSplit2[iIntValue].length() + length4;
                    if (length4 > length5) {
                        continue;
                    } else {
                        AztecPreformatSpan[] aztecPreformatSpanArr = (AztecPreformatSpan[]) u().getSpans(length4, length5, AztecPreformatSpan.class);
                        Intrinsics.d(aztecPreformatSpanArr);
                        for (AztecPreformatSpan aztecPreformatSpan : aztecPreformatSpanArr) {
                            int spanEnd = u().getSpanEnd(aztecPreformatSpan);
                            if (spanEnd != length4 || u().charAt(spanEnd) != '\n') {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public final boolean d0(int i, int i2) {
        if (i >= 0 && i2 >= 0) {
            Object[] spans = u().getSpans(i, i2, C5168p.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (Object obj : spans) {
                C5168p c5168p = (C5168p) obj;
                int spanStart = u().getSpanStart(c5168p);
                int spanEnd = u().getSpanEnd(c5168p);
                if (i != i2) {
                    if (spanStart <= i && i <= spanEnd) {
                        return true;
                    }
                    if (spanStart <= i2 && i2 <= spanEnd) {
                        return true;
                    }
                    if ((i <= spanStart && spanStart <= i2) || spanStart <= spanEnd) {
                        return true;
                    }
                } else if (u().length() == i) {
                    if (spanStart <= i && i <= spanEnd) {
                        return true;
                    }
                } else if (spanEnd != i && spanStart <= i && i <= spanEnd) {
                    return true;
                }
            }
        }
        return false;
    }

    public final List e0(int i, int i2, G g) {
        if (i < 0 || i2 < 0) {
            return K.a;
        }
        Object[] spans = u().getSpans(i, i2, B.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        ArrayList arrayList = new ArrayList();
        for (Object obj : spans) {
            B b = (B) obj;
            if (g == null || b.d() == f0(g, StringsKt.Y(u(), kotlin.ranges.l.h(u().getSpanStart(b), u().getSpanEnd(b))))) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            B b2 = (B) next;
            int spanStart = u().getSpanStart(b2);
            int spanEnd = u().getSpanEnd(b2);
            if (i == i2) {
                if (u().length() == i) {
                    if (spanStart <= i && i <= spanEnd) {
                        arrayList2.add(next);
                    }
                } else if (spanEnd != i && spanStart <= i && i <= spanEnd) {
                    arrayList2.add(next);
                }
            } else if ((spanStart <= i && i <= spanEnd) || ((spanStart <= i2 && i2 <= spanEnd) || ((i <= spanStart && spanStart <= i2) || (i <= spanEnd && spanEnd <= i2)))) {
                arrayList2.add(next);
            }
        }
        return arrayList2;
    }

    public final IntRange g0(Editable editable, int i, int i2) {
        int iQ;
        Intrinsics.checkNotNullParameter(editable, "editable");
        boolean z = i != i2 && i > 0 && i < u().length() && editable.charAt(i) == '\n';
        boolean z2 = z && i > 0 && i < u().length() && editable.charAt(i + (-1)) == '\n';
        boolean z3 = i != i2 && i2 > 0 && u().length() > i2 && u().charAt(i2) != C2.i && u().charAt(i2) != '\n' && u().charAt(i2 + (-1)) == '\n';
        int iM = StringsKt.M(editable, "\n", i2, false, 4);
        if (!z2) {
            if (z) {
                i = ((i <= 1 || u().charAt(i + (-1)) == '\n' || u().charAt(i + (-2)) != '\n') && i != 1) ? StringsKt.Q(editable, "\n", i - 1, 4) + 1 : i - 1;
                if (z3) {
                    iM = StringsKt.M(editable, "\n", i2 - 1, false, 4);
                }
            } else if (z3) {
                i = StringsKt.Q(editable, "\n", i - 1, 4) + 1;
                iM = StringsKt.M(editable, "\n", i2 - 1, false, 4);
            } else {
                if (iM > 0) {
                    iQ = StringsKt.Q(editable, "\n", i - 1, 4);
                } else if (iM != -1) {
                    i = StringsKt.Q(editable, "\n", i, 4);
                } else if (i == 0) {
                    i = 0;
                } else {
                    iQ = StringsKt.Q(editable, "\n", i, 4);
                }
                i = iQ + 1;
            }
        }
        return new IntRange(i != -1 ? i : 0, iM != -1 ? iM + 1 : editable.length(), 1);
    }

    public final void h0(int i, int i2, G g) {
        if (g == x.i) {
            i0(i, i2, AztecOrderedListSpan.class);
            return;
        }
        if (g == x.h) {
            i0(i, i2, AztecUnorderedListSpan.class);
            return;
        }
        if (g == x.j) {
            i0(i, i2, AztecTaskListSpan.class);
            return;
        }
        int i3 = 0;
        if (g == x.u) {
            Object[] spans = u().getSpans(i, i2, C5168p.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            int length = spans.length;
            while (i3 < length) {
                C5168p c5168p = (C5168p) spans[i3];
                C5174w.e(u(), i, i2, c5168p.a);
                u().removeSpan(c5168p);
                i3++;
            }
            return;
        }
        Object[] spans2 = u().getSpans(i, i2, T.class);
        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
        int length2 = spans2.length;
        while (i3 < length2) {
            T t = (T) spans2[i3];
            C5174w.e(u(), i, i2, t.a);
            u().removeSpan(t);
            i3++;
        }
    }

    public final void i0(int i, int i2, Class cls) {
        Object[] spans = u().getSpans(i, i2, cls);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            AztecListSpan aztecListSpan = (AztecListSpan) obj;
            Editable spannable = u();
            Intrinsics.checkNotNullParameter(spannable, "spannable");
            Object[] spans2 = u().getSpans(spannable.getSpanStart(aztecListSpan), spannable.getSpanEnd(aztecListSpan), C5164l.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            for (Object obj2 : spans2) {
                u().removeSpan((C5164l) obj2);
            }
            C5174w.e(u(), i, i2, aztecListSpan.a());
            spannable.getSpanStart(aztecListSpan);
            spannable.getSpanEnd(aztecListSpan);
            spannable.getSpanFlags(aztecListSpan);
            spannable.removeSpan(aztecListSpan);
        }
    }

    public final List j0(G textFormat, int i, C5146b attrs) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        x xVar = x.i;
        e eVar = this.c;
        EnumC5145a enumC5145a = this.h;
        if (textFormat == xVar) {
            return kotlin.collections.B.j(O2.a(i, enumC5145a, attrs, eVar), N2.b(i + 1, enumC5145a, null, null, 12));
        }
        if (textFormat == x.h) {
            return kotlin.collections.B.j(S2.e(i, enumC5145a, attrs, eVar), N2.b(i + 1, enumC5145a, null, null, 12));
        }
        if (textFormat != x.j) {
            return textFormat == x.u ? A.b(Q2.a(i, attrs, enumC5145a, this.e)) : (textFormat == x.b || textFormat == x.c || textFormat == x.d || textFormat == x.e || textFormat == x.f || textFormat == x.g) ? A.b(M2.d(i, textFormat, attrs, enumC5145a, this.f)) : textFormat == x.y ? A.b(P2.a(i, enumC5145a, attrs, this.g)) : A.b(X2.b(i, enumC5145a, attrs, this.j));
        }
        Context context = ((AztecText) this.b).getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return kotlin.collections.B.j(R2.c(i, enumC5145a, attrs, context, eVar), N2.b(i + 1, enumC5145a, null, this.d, 4));
    }

    public final D l0(C4950i c4950i, G g, int i, C5146b c5146b) {
        androidx.credentials.playservices.controllers.BeginSignIn.c cVar = new androidx.credentials.playservices.controllers.BeginSignIn.c(c4950i, 21);
        boolean zBooleanValue = ((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(AztecOrderedListSpan.class))).booleanValue();
        e eVar = this.c;
        EnumC5145a enumC5145a = this.h;
        if (zBooleanValue) {
            return O2.a(i, enumC5145a, c5146b, eVar);
        }
        if (((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(AztecUnorderedListSpan.class))).booleanValue()) {
            return S2.e(i, enumC5145a, c5146b, eVar);
        }
        if (!((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(AztecTaskListSpan.class))).booleanValue()) {
            return ((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(C5164l.class))).booleanValue() ? N2.a(i, enumC5145a, c5146b, this.d) : ((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(C5168p.class))).booleanValue() ? Q2.a(i, c5146b, enumC5145a, this.e) : ((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(C5160h.class))).booleanValue() ? M2.d(i, g, c5146b, enumC5145a, this.f) : ((Boolean) cVar.invoke(kotlin.jvm.internal.K.a(AztecPreformatSpan.class))).booleanValue() ? P2.a(i, enumC5145a, c5146b, this.g) : X2.b(i, enumC5145a, c5146b, this.j);
        }
        Context context = ((AztecText) this.b).getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return R2.c(i, enumC5145a, c5146b, context, eVar);
    }

    public final D m0(G textFormat, int i, C5146b attrs) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        return textFormat == x.i ? l0(kotlin.jvm.internal.K.a(AztecOrderedListSpan.class), textFormat, i, attrs) : textFormat == x.h ? l0(kotlin.jvm.internal.K.a(AztecUnorderedListSpan.class), textFormat, i, attrs) : textFormat == x.j ? l0(kotlin.jvm.internal.K.a(AztecTaskListSpan.class), textFormat, i, attrs) : textFormat == x.u ? l0(kotlin.jvm.internal.K.a(C5168p.class), textFormat, i, attrs) : (textFormat == x.b || textFormat == x.c || textFormat == x.d || textFormat == x.e || textFormat == x.f || textFormat == x.g) ? l0(kotlin.jvm.internal.K.a(C5160h.class), textFormat, i, attrs) : textFormat == x.y ? l0(kotlin.jvm.internal.K.a(AztecPreformatSpan.class), textFormat, i, attrs) : X2.b(i, this.h, attrs, this.j);
    }

    public final void o0(int i, int i2, G g) {
        int i3;
        int i4;
        int iB = C5174w.b(u(), i, i2);
        int i5 = iB + 1;
        Object[] spans = u().getSpans(i, i2, E.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        int length = spans.length;
        int i6 = 0;
        while (true) {
            if (i6 >= length) {
                break;
            }
            if (((C5164l) ((E) spans[i6])).a == i5) {
                i5 = iB + 2;
                break;
            }
            i6++;
        }
        D dN0 = n0(this, g, i5);
        int i7 = dN0 instanceof AztecListSpan ? 2 : 1;
        Editable spannable = u();
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(org.wordpress.aztec.spans.K.class, DBUserFields.Names.USER_UPGRADE_TYPE);
        Object[] spanObjects = spannable.getSpans(i, i2, org.wordpress.aztec.spans.K.class);
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
            org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) next;
            if (spannable.getSpanStart(dVar.b) >= i && spannable.getSpanEnd(dVar.b) <= i2) {
                arrayList2.add(next);
            }
        }
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            Object next2 = it3.next();
            if (((org.wordpress.aztec.spans.K) ((org.wordpress.aztec.util.d) next2).b).a() >= i5) {
                arrayList3.add(next2);
            }
        }
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            org.wordpress.aztec.spans.K k = (org.wordpress.aztec.spans.K) ((org.wordpress.aztec.util.d) it4.next()).b;
            k.t(k.a() + i7);
        }
        Iterator it5 = arrayList3.iterator();
        while (it5.hasNext()) {
            ((org.wordpress.aztec.util.d) it5.next()).c();
        }
        T(dN0, i, i2);
        Iterator it6 = arrayList3.iterator();
        while (it6.hasNext()) {
            org.wordpress.aztec.util.d dVar2 = (org.wordpress.aztec.util.d) it6.next();
            int i8 = dVar2.e;
            if (i8 != -1 && (i3 = dVar2.d) != -1 && (i4 = dVar2.c) != -1) {
                dVar2.e(dVar2.b, i4, i3, i8);
            }
        }
    }

    public final void p0(G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        AztecText aztecText = (AztecText) this.b;
        int selectionStart = aztecText.getSelectionStart();
        int selectionEnd = aztecText.getSelectionEnd();
        List listK0 = k0(this, textFormat);
        ArrayList arrayList = new ArrayList(C.q(listK0, 10));
        Iterator it2 = listK0.iterator();
        while (it2.hasNext()) {
            arrayList.add(((D) it2.next()).getClass());
        }
        q0(textFormat, selectionStart, selectionEnd, arrayList, false);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0120 A[EDGE_INSN: B:85:0x0120->B:46:0x0120 BREAK  A[LOOP:2: B:29:0x00a8->B:88:?], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void q0(org.wordpress.aztec.G r19, int r20, int r21, java.util.List r22, boolean r23) {
        /*
            Method dump skipped, instructions count: 509
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.formatting.i.q0(org.wordpress.aztec.G, int, int, java.util.List, boolean):void");
    }

    public final void r0(Class type) {
        Intrinsics.checkNotNullParameter(type, "type");
        Editable editableU = u();
        AztecText aztecText = (AztecText) this.b;
        Object[] spans = editableU.getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), type);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            D d = (D) obj;
            C5174w.e(u(), aztecText.getSelectionStart(), aztecText.getSelectionEnd(), d.a());
            u().removeSpan(d);
        }
    }

    public final void t0(x xVar) {
        Set set = this.k;
        ArrayList arrayList = new ArrayList();
        for (Object obj : set) {
            if (((x) obj) != xVar) {
                arrayList.add(obj);
            }
        }
        boolean zA0 = a0(this, xVar);
        AztecText aztecText = (AztecText) this.b;
        if (zA0) {
            if (!arrayList.isEmpty()) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (a0(this, (x) it2.next())) {
                        s0(this, xVar);
                        aztecText.d(u(), aztecText.getSelectionStart(), aztecText.getSelectionEnd());
                        return;
                    }
                }
            }
            p0(xVar);
            return;
        }
        if (!arrayList.isEmpty()) {
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                if (a0(this, (x) it3.next())) {
                    s0(this, xVar);
                    aztecText.d(u(), aztecText.getSelectionStart(), aztecText.getSelectionEnd());
                    return;
                }
            }
        }
        U(this, xVar);
        aztecText.d(u(), aztecText.getSelectionStart(), aztecText.getSelectionEnd());
    }
}
