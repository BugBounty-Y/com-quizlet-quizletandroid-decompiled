package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.exceptions.NetException;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.NetworkException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V {
    public static final void a(androidx.compose.foundation.contextmenu.o oVar, Function0 function0, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(645832757);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(oVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.contextmenu.n nVar = (androidx.compose.foundation.contextmenu.n) ((androidx.compose.runtime.L0) oVar.a).getValue();
            if (!(nVar instanceof androidx.compose.foundation.contextmenu.m)) {
                C0813o0 c0813o0R = c0814p.r();
                if (c0813o0R != null) {
                    c0813o0R.d = new androidx.compose.foundation.contextmenu.a(oVar, function0, function1, i);
                    return;
                }
                return;
            }
            boolean zF = c0814p.f(nVar);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                objI = new androidx.compose.foundation.contextmenu.h(P5.e(((androidx.compose.foundation.contextmenu.m) nVar).a));
                c0814p.i0(objI);
            }
            androidx.compose.foundation.contextmenu.q.d((androidx.compose.foundation.contextmenu.h) objI, function0, function1, c0814p, i3 & 8176);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R2 = c0814p.r();
        if (c0813o0R2 != null) {
            c0813o0R2.d = new androidx.compose.foundation.contextmenu.b(oVar, function0, qVar2, function1, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00ca  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0115  */
    /* JADX WARN: Removed duplicated region for block: B:71:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.foundation.contextmenu.o r16, kotlin.jvm.functions.Function0 r17, kotlin.jvm.functions.Function1 r18, androidx.compose.ui.n r19, boolean r20, androidx.compose.runtime.internal.d r21, androidx.compose.runtime.InterfaceC0806l r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.V.b(androidx.compose.foundation.contextmenu.o, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.ui.n, boolean, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final Object c(ApiThreeWrapper apiThreeWrapper, Function1 function1) {
        String str;
        ApiResponse apiResponseA = apiThreeWrapper.a();
        if (apiResponseA != null) {
            kotlin.p pVar = kotlin.r.b;
            return function1.invoke(apiResponseA);
        }
        kotlin.p pVar2 = kotlin.r.b;
        ApiError apiError = apiThreeWrapper.b;
        if (apiError == null || (str = apiError.a) == null) {
            str = "Request failed with no response or error";
        }
        return androidx.glance.appwidget.protobuf.Z.b(new NetworkException(apiError, str, new NetException(apiError != null ? apiError.a : null)));
    }

    public static final Object d(androidx.compose.material3.O3 o3, boolean z, Context context, kotlin.coroutines.jvm.internal.i iVar) {
        String string = context.getString(z ? R.string.resend_confirmation_success_message : R.string.unable_to_reach_quizlet_msg);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        Object objB = androidx.compose.material3.O3.b(o3, string, iVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }
}
