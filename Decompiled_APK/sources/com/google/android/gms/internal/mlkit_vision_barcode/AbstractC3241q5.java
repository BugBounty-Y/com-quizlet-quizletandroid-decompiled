package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Paint;
import android.text.Layout;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.basestudy.data.models.MeteredValue;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.q5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3241q5 {
    /* JADX WARN: Removed duplicated region for block: B:40:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:61:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.q r19, long r20, long r22, com.quizlet.ui.compose.EnumC4819l r24, androidx.compose.runtime.InterfaceC0806l r25, int r26, int r27) {
        /*
            Method dump skipped, instructions count: 217
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5.a(androidx.compose.ui.q, long, long, com.quizlet.ui.compose.l, androidx.compose.runtime.l, int, int):void");
    }

    public static final float b(Layout layout, int i, Paint paint) {
        float fAbs;
        float width;
        float lineLeft = layout.getLineLeft(i);
        androidx.compose.ui.text.android.w wVar = androidx.compose.ui.text.android.y.a;
        if (layout.getEllipsisCount(i) <= 0 || layout.getParagraphDirection(i) != 1 || lineLeft >= DefinitionKt.NO_Float_VALUE) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float fMeasureText = paint.measureText("…") + (layout.getPrimaryHorizontal(layout.getEllipsisStart(i) + layout.getLineStart(i)) - lineLeft);
        Layout.Alignment paragraphAlignment = layout.getParagraphAlignment(i);
        if ((paragraphAlignment == null ? -1 : androidx.compose.ui.text.android.style.d.a[paragraphAlignment.ordinal()]) == 1) {
            fAbs = Math.abs(lineLeft);
            width = (layout.getWidth() - fMeasureText) / 2.0f;
        } else {
            fAbs = Math.abs(lineLeft);
            width = layout.getWidth() - fMeasureText;
        }
        return width + fAbs;
    }

    public static final float c(Layout layout, int i, Paint paint) {
        float width;
        float width2;
        androidx.compose.ui.text.android.w wVar = androidx.compose.ui.text.android.y.a;
        if (layout.getEllipsisCount(i) <= 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        if (layout.getParagraphDirection(i) != -1 || layout.getWidth() >= layout.getLineRight(i)) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float fMeasureText = paint.measureText("…") + (layout.getLineRight(i) - layout.getPrimaryHorizontal(layout.getEllipsisStart(i) + layout.getLineStart(i)));
        Layout.Alignment paragraphAlignment = layout.getParagraphAlignment(i);
        if ((paragraphAlignment != null ? androidx.compose.ui.text.android.style.d.a[paragraphAlignment.ordinal()] : -1) == 1) {
            width = layout.getWidth() - layout.getLineRight(i);
            width2 = (layout.getWidth() - fMeasureText) / 2.0f;
        } else {
            width = layout.getWidth() - layout.getLineRight(i);
            width2 = layout.getWidth() - fMeasureText;
        }
        return width - width2;
    }

    public static final boolean d(MeteredValue meteredValue) {
        Intrinsics.checkNotNullParameter(meteredValue, "<this>");
        return meteredValue == MeteredValue.a || meteredValue == MeteredValue.b;
    }

    public static final MeteredValue e(InterfaceC4176w0 interfaceC4176w0) {
        Intrinsics.checkNotNullParameter(interfaceC4176w0, "<this>");
        if (!(interfaceC4176w0 instanceof com.quizlet.data.model.o2)) {
            if (interfaceC4176w0 instanceof C4179x0) {
                return MeteredValue.b;
            }
            throw new NoWhenBranchMatchedException();
        }
        com.quizlet.data.model.o2 o2Var = (com.quizlet.data.model.o2) interfaceC4176w0;
        o2Var.getClass();
        switch (com.quizlet.data.model.n2.a[o2Var.d.ordinal()]) {
            case 1:
            case 2:
                return MeteredValue.a;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                return MeteredValue.c;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
