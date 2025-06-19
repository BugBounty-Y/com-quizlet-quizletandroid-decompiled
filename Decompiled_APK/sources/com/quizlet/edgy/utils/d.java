package com.quizlet.edgy.utils;

import android.text.Editable;
import android.text.Spannable;
import android.text.TextWatcher;
import android.widget.EditText;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.partskit.widgets.QButton;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.formatting.l;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.watchers.h;

/* loaded from: classes2.dex */
public final class d implements TextWatcher {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public d() {
        this.a = 0;
        this.d = e.a;
    }

    private final void b(Editable editable) {
    }

    private final void c(int i, int i2, int i3, CharSequence charSequence) {
    }

    public static void d(Editable text, Class spanClass) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(spanClass, "spanClass");
        Object[] spans = text.getSpans(0, 0, spanClass);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            if (text.length() > 0) {
                text.setSpan(obj, 0, text.getSpanEnd(obj), text.getSpanFlags(obj));
            } else {
                text.removeSpan(obj);
            }
        }
    }

    public void a(org.wordpress.aztec.handlers.b textChangeHandler) {
        Intrinsics.checkNotNullParameter(textChangeHandler, "textChangeHandler");
        ((ArrayList) this.b).add(textChangeHandler);
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x00c6  */
    @Override // android.text.TextWatcher
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void afterTextChanged(android.text.Editable r12) {
        /*
            Method dump skipped, instructions count: 494
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.utils.d.afterTextChanged(android.text.Editable):void");
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        AztecText aztecText;
        switch (this.a) {
            case 0:
                break;
            case 1:
                Intrinsics.checkNotNullParameter(text, "text");
                if (i2 > 0) {
                    int i4 = i + i2;
                    int i5 = i4 - 1;
                    if (text.charAt(i5) == '\n') {
                        if (i5 == 0 || text.charAt(i4 - 2) == '\n') {
                            Spannable spannable = (Spannable) text;
                            Intrinsics.checkNotNullParameter(spannable, "spannable");
                            Intrinsics.checkNotNullParameter(C5160h.class, DBUserFields.Names.USER_UPGRADE_TYPE);
                            Object[] spanObjects = spannable.getSpans(i4, i4, C5160h.class);
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
                                if (((org.wordpress.aztec.util.d) next).b() == i4) {
                                    arrayList2.add(next);
                                }
                            }
                            if (!arrayList2.isEmpty() && (aztecText = (AztecText) ((WeakReference) this.c).get()) != null) {
                                aztecText.getHistory().a(aztecText);
                                aztecText.setConsumeHistoryEvent(false);
                                Iterator it3 = arrayList2.iterator();
                                while (it3.hasNext()) {
                                    org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) it3.next();
                                    int iA = ((C5160h) dVar.b).a();
                                    C5160h c5160h = (C5160h) dVar.b;
                                    spannable.setSpan(M2.c(iA, c5160h.k().b, c5160h.f(), (EnumC5145a) this.d, c5160h.e()), i5, i4, dVar.a.getSpanFlags(dVar.b));
                                }
                                aztecText.setConsumeHistoryEvent(true);
                                break;
                            }
                        }
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                AztecText aztecText2 = (AztecText) ((WeakReference) this.c).get();
                if (!(aztecText2 != null ? aztecText2.m : true)) {
                    this.d = new h(text.toString(), 6);
                    break;
                }
                break;
        }
    }

    public void e() {
        QButton qButton = (QButton) this.b;
        if (qButton != null) {
            int iOrdinal = ((e) this.d).ordinal();
            boolean z = false;
            if (iOrdinal == 0) {
                Collection collection = (List) this.c;
                if (collection == null) {
                    collection = K.a;
                }
                if (collection != null && collection.isEmpty()) {
                    z = true;
                    break;
                }
                Iterator it2 = collection.iterator();
                while (it2.hasNext()) {
                    Editable text = ((EditText) it2.next()).getText();
                    if (text == null || StringsKt.O(text)) {
                        break;
                    }
                }
                z = true;
                break;
            }
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            Collection collection2 = (List) this.c;
            if (collection2 == null) {
                collection2 = K.a;
            }
            if (collection2 == null || !collection2.isEmpty()) {
                Iterator it3 = collection2.iterator();
                while (it3.hasNext()) {
                    Editable text2 = ((EditText) it3.next()).getText();
                    if (text2 != null && !StringsKt.O(text2)) {
                        z = true;
                        break;
                    }
                }
            }
            qButton.setEnabled(z);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x021f  */
    @Override // android.text.TextWatcher
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onTextChanged(java.lang.CharSequence r23, int r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 712
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.utils.d.onTextChanged(java.lang.CharSequence, int, int, int):void");
    }

    public d(AztecText aztecText) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.b = new ArrayList();
        this.c = new WeakReference(aztecText);
        this.d = aztecText.getAlignmentRendering();
    }

    public d(l inlineFormatter, AztecText aztecText) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(inlineFormatter, "inlineFormatter");
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.b = inlineFormatter;
        this.c = new WeakReference(aztecText);
        this.d = new h();
    }
}
