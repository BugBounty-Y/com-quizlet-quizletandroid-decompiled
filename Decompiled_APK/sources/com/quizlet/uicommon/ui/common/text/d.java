package com.quizlet.uicommon.ui.common.text;

import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.method.LinkMovementMethod;
import android.view.MotionEvent;
import android.widget.TextView;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class d extends LinkMovementMethod {
    public static final u b = l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(24));
    public com.quizlet.uicommon.util.b a;

    public static com.quizlet.uicommon.util.b a(TextView textView, Spannable spannable, MotionEvent motionEvent) {
        int scrollX = textView.getScrollX() + (((int) motionEvent.getX()) - textView.getTotalPaddingLeft());
        int scrollY = textView.getScrollY() + (((int) motionEvent.getY()) - textView.getTotalPaddingTop());
        Layout layout = textView.getLayout();
        int offsetForHorizontal = layout.getOffsetForHorizontal(layout.getLineForVertical(scrollY), scrollX);
        com.quizlet.uicommon.util.b[] bVarArr = (com.quizlet.uicommon.util.b[]) spannable.getSpans(offsetForHorizontal, offsetForHorizontal, com.quizlet.uicommon.util.b.class);
        Intrinsics.d(bVarArr);
        if (bVarArr.length == 0) {
            return null;
        }
        com.quizlet.uicommon.util.b bVar = bVarArr[0];
        Intrinsics.checkNotNullExpressionValue(bVar, "get(...)");
        if (offsetForHorizontal < spannable.getSpanStart(bVar) || offsetForHorizontal > spannable.getSpanEnd(bVar)) {
            return null;
        }
        return bVarArr[0];
    }

    @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
    public final boolean onTouchEvent(TextView textView, Spannable spannable, MotionEvent event) {
        Intrinsics.checkNotNullParameter(textView, "textView");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(event, "event");
        if (event.getAction() == 0) {
            com.quizlet.uicommon.util.b bVarA = a(textView, spannable, event);
            this.a = bVarA;
            if (bVarA != null) {
                bVarA.c = true;
                Selection.setSelection(spannable, spannable.getSpanStart(bVarA), spannable.getSpanEnd(this.a));
                return true;
            }
        } else {
            if (event.getAction() != 2) {
                com.quizlet.uicommon.util.b bVar = this.a;
                if (bVar != null) {
                    bVar.c = false;
                    super.onTouchEvent(textView, spannable, event);
                }
                this.a = null;
                Selection.removeSelection(spannable);
                return true;
            }
            com.quizlet.uicommon.util.b bVarA2 = a(textView, spannable, event);
            com.quizlet.uicommon.util.b bVar2 = this.a;
            if (bVar2 != null && !Intrinsics.b(bVarA2, bVar2)) {
                com.quizlet.uicommon.util.b bVar3 = this.a;
                Intrinsics.d(bVar3);
                bVar3.c = false;
                this.a = null;
                Selection.removeSelection(spannable);
            }
        }
        return true;
    }
}
