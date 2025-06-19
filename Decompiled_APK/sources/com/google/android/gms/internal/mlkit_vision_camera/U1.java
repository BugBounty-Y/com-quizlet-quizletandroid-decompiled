package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U1 {
    public final /* synthetic */ int a = 3;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, com.quizlet.assembly.compose.modals.x state, Function0 onSubmitTestClick, Function1 onRowClick, kotlinx.collections.immutable.e questionList) {
        int i2;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(questionList, "questionList");
        Intrinsics.checkNotNullParameter(onRowClick, "onRowClick");
        Intrinsics.checkNotNullParameter(onSubmitTestClick, "onSubmitTestClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1571518414);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(state) : c0814p.h(state) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(questionList) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onRowClick) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(onSubmitTestClick) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            U5.b(state, androidx.compose.ui.platform.N.G(qVar, "practice_test_question_list_modal"), false, null, null, null, androidx.compose.runtime.internal.e.e(823258995, new com.quizlet.assembly.compose.buttons.A(questionList, onRowClick, state, onSubmitTestClick, 14), c0814p), c0814p, 1572872 | (i2 & 14), 60);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.common.composables.l(state, questionList, onRowClick, onSubmitTestClick, qVar, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x01f1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x01fa  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(kotlinx.collections.immutable.e r22, kotlin.jvm.functions.Function1 r23, kotlin.jvm.functions.Function0 r24, androidx.compose.runtime.InterfaceC0806l r25, int r26) {
        /*
            Method dump skipped, instructions count: 564
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.U1.b(kotlinx.collections.immutable.e, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int):void");
    }

    public static String c(String tableName, String triggerType) {
        Intrinsics.checkNotNullParameter(tableName, "tableName");
        Intrinsics.checkNotNullParameter(triggerType, "triggerType");
        return "`room_table_modification_trigger_" + tableName + '_' + triggerType + '`';
    }

    public int hashCode() {
        switch (this.a) {
            case 3:
                return toString().hashCode();
            default:
                return super.hashCode();
        }
    }

    public String toString() {
        switch (this.a) {
            case 3:
                String strF = kotlin.jvm.internal.K.a(getClass()).f();
                Intrinsics.d(strF);
                return strF;
            default:
                return super.toString();
        }
    }
}
