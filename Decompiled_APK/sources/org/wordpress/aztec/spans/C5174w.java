package org.wordpress.aztec.spans;

import android.content.Context;
import android.text.Editable;
import android.text.Spannable;
import android.text.Spanned;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5174w {
    public static HighlightSpan a(C5146b attributes, Context context, org.wordpress.aztec.formatting.k kVar, int i) {
        int color;
        int i2 = HighlightSpan.c;
        if ((i & 1) != 0) {
            attributes = new C5146b();
        }
        if ((i & 4) != 0) {
            kVar = null;
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(context, "context");
        if (H2.b(attributes)) {
            String strD = H2.d("background-color", attributes);
            Object obj = org.wordpress.aztec.util.c.a;
            color = org.wordpress.aztec.util.b.c(strD);
        } else {
            color = kVar != null ? context.getColor(kVar.a) : context.getColor(R.color.grey_lighten_10);
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        HighlightSpan highlightSpan = new HighlightSpan(color);
        highlightSpan.a = attributes;
        highlightSpan.b = "highlight";
        return highlightSpan;
    }

    public static int b(Editable spanned, int i, int i2) {
        Object obj;
        Intrinsics.checkNotNullParameter(spanned, "spanned");
        Object[] spans = spanned.getSpans(i, i2, K.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        ArrayList arrayList = new ArrayList();
        for (Object obj2 : spans) {
            if (spanned.getSpanEnd((K) obj2) != i || i == 0 || spanned.charAt(i - 1) != C2.g) {
                arrayList.add(obj2);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            K k = (K) next;
            if (spanned.getSpanStart(k) <= i && spanned.getSpanEnd(k) >= i2 && (spanned.getSpanStart(k) != i || spanned.getSpanEnd(k) != i2)) {
                arrayList2.add(next);
            }
        }
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            Object next2 = it3.next();
            K k2 = (K) next2;
            if (i != i2 || (spanned.getSpanStart(k2) != i && spanned.getSpanEnd(k2) != i)) {
                arrayList3.add(next2);
            }
        }
        Iterator it4 = arrayList3.iterator();
        if (it4.hasNext()) {
            Object next3 = it4.next();
            if (it4.hasNext()) {
                int iA = ((K) next3).a();
                do {
                    Object next4 = it4.next();
                    int iA2 = ((K) next4).a();
                    if (iA > iA2) {
                        next3 = next4;
                        iA = iA2;
                    }
                } while (it4.hasNext());
            }
            obj = next3;
        } else {
            obj = null;
        }
        K k3 = (K) obj;
        if (k3 != null) {
            return k3.a();
        }
        return 0;
    }

    public static int c(Spanned spanned, int i, int i2) {
        Object obj;
        Intrinsics.checkNotNullParameter(spanned, "spanned");
        Object[] spans = spanned.getSpans(i, i2, K.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        ArrayList arrayList = new ArrayList();
        for (Object obj2 : spans) {
            if (spanned.getSpanEnd((K) obj2) != i || i == 0 || spanned.charAt(i - 1) != C2.g) {
                arrayList.add(obj2);
            }
        }
        Iterator it2 = arrayList.iterator();
        if (it2.hasNext()) {
            Object next = it2.next();
            if (it2.hasNext()) {
                int iA = ((K) next).a();
                do {
                    Object next2 = it2.next();
                    int iA2 = ((K) next2).a();
                    if (iA < iA2) {
                        next = next2;
                        iA = iA2;
                    }
                } while (it2.hasNext());
            }
            obj = next;
        } else {
            obj = null;
        }
        K k = (K) obj;
        if (k != null) {
            return k.a();
        }
        return 0;
    }

    public static org.wordpress.aztec.util.d d(Spannable spannable, org.wordpress.aztec.util.d child) {
        Object objPrevious;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(child, "child");
        Object[] spanObjects = spannable.getSpans(child.b(), child.b() + 1, K.class);
        Intrinsics.checkNotNullExpressionValue(spanObjects, "getSpans(...)");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(spanObjects, "spanObjects");
        ArrayList arrayList = new ArrayList(spanObjects.length);
        for (Object obj : spanObjects) {
            arrayList.add(new org.wordpress.aztec.util.d(spannable, obj));
        }
        List listN0 = CollectionsKt.n0(arrayList, new J());
        ListIterator listIterator = listN0.listIterator(listN0.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                objPrevious = null;
                break;
            }
            objPrevious = listIterator.previous();
            if (((K) ((org.wordpress.aztec.util.d) objPrevious).b).a() < ((K) child.b).a()) {
                break;
            }
        }
        return (org.wordpress.aztec.util.d) objPrevious;
    }

    public static void e(Editable spannable, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(K.class, DBUserFields.Names.USER_UPGRADE_TYPE);
        Object[] spanObjects = spannable.getSpans(i, i2, K.class);
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
            if (((K) ((org.wordpress.aztec.util.d) next2).b).a() >= i3) {
                arrayList3.add(next2);
            }
        }
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            ((K) ((org.wordpress.aztec.util.d) it4.next()).b).t(r7.a() - 1);
        }
    }
}
