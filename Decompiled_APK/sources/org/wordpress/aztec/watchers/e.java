package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.Spannable;
import android.text.TextWatcher;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.O;

/* loaded from: classes3.dex */
public final class e implements TextWatcher {
    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        Intrinsics.checkNotNullParameter(s, "s");
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
        if (i + i2 >= s.length() && i2 != 0) {
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
                org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) next;
                if (dVar.b() == i && dVar.a() > i) {
                    arrayList2.add(next);
                }
            }
            Iterator it3 = arrayList2.iterator();
            while (it3.hasNext()) {
                ((O) ((org.wordpress.aztec.util.d) it3.next()).b).j(i);
            }
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
        if (i3 == 0) {
            return;
        }
        Spannable spannable = (Spannable) s;
        int length = s.length();
        int length2 = s.length();
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(O.class, DBUserFields.Names.USER_UPGRADE_TYPE);
        Object[] spanObjects = spannable.getSpans(length, length2, O.class);
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
            if (((O) ((org.wordpress.aztec.util.d) next).b).s()) {
                arrayList2.add(next);
            }
        }
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) it3.next();
            dVar.e(dVar.b, ((O) dVar.b).b(), dVar.a(), dVar.a.getSpanFlags(dVar.b));
            ((O) dVar.b).o();
        }
    }
}
