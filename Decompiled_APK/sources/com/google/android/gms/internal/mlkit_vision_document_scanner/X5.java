package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Rect;
import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import com.quizlet.quizletandroid.R;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class X5 {
    public static final void a(final String message, androidx.compose.ui.n nVar, final String str, final String str2, final String str3, final int i, final boolean z, String str4, final Function1 function1, String str5, final Function0 function0, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        int i4;
        int i5;
        androidx.compose.ui.n nVar2;
        String strD;
        String str6;
        final String str7;
        final String str8;
        final androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(message, "message");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-872092098);
        if ((i2 & 6) == 0) {
            i4 = (c0814p.f(message) ? 4 : 2) | i2;
        } else {
            i4 = i2;
        }
        int i6 = i4 | 48;
        if ((i2 & 384) == 0) {
            i6 |= c0814p.f(str) ? 256 : 128;
        }
        int i7 = i6 | 3072;
        if ((i2 & 24576) == 0) {
            i7 |= c0814p.f(str2) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i7 |= c0814p.f(str3) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i7 |= c0814p.d(i) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i7 |= c0814p.g(z) ? 8388608 : 4194304;
        }
        if ((100663296 & i2) == 0) {
            i7 |= 33554432;
        }
        if ((805306368 & i2) == 0) {
            i7 |= c0814p.h(function1) ? 536870912 : 268435456;
        }
        int i8 = (i3 & 6) == 0 ? i3 | 2 : i3;
        if ((i3 & 48) == 0) {
            i8 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((306783379 & i7) == 306783378 && (i8 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            str8 = str4;
            str7 = str5;
        } else {
            c0814p.S();
            int i9 = i2 & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i9 == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
                String strD2 = AbstractC3106b5.d(c0814p, R.string.submit);
                i5 = i7 & (-234881025);
                nVar2 = nVar4;
                strD = AbstractC3106b5.d(c0814p, R.string.cancel);
                str6 = strD2;
            } else {
                c0814p.Q();
                i5 = i7 & (-234881025);
                nVar2 = nVar;
                str6 = str4;
                strD = str5;
            }
            c0814p.q();
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p.j(AbstractC0955m0.n);
            Object[] objArr = new Object[0];
            c0814p.X(-6627583);
            boolean z2 = (i5 & 7168) == 2048;
            Object objI = c0814p.I();
            if (z2 || objI == v) {
                objI = new com.quizlet.assembly.compose.listitems.r(12);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            int i10 = i5;
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(30116348, new com.quizlet.assembly.compose.modals.v(message, interfaceC0773a0, str2, i, q0, function1, str3, z), c0814p);
            c0814p.X(-6602726);
            androidx.compose.runtime.internal.d dVarE2 = str == null ? null : androidx.compose.runtime.internal.e.e(627912738, new com.quizlet.assembly.compose.input.i(str, 3), c0814p);
            c0814p.p(false);
            String str9 = strD;
            androidx.compose.ui.n nVar5 = nVar2;
            AbstractC3579a6.d(nVar5, dVarE, dVarE2, androidx.compose.runtime.internal.e.e(2064090263, new com.quizlet.assembly.compose.menu.g((Object) str6, (Object) q0, (InterfaceC4938g) function1, (Object) interfaceC0773a0, 1), c0814p), androidx.compose.runtime.internal.e.e(-677789672, new com.quizlet.assembly.compose.input.h(2, str9, q0, function0, false), c0814p), 0, false, c0814p, ((i10 >> 3) & 14) | 27696, 96);
            c0814p = c0814p;
            str7 = str9;
            str8 = str6;
            nVar3 = nVar5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.modals.s
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int iH2 = C0776c.H(i3);
                    String str10 = str7;
                    Function0 function02 = function0;
                    X5.a(message, nVar3, str, str2, str3, i, z, str8, function1, str10, function02, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00c3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.recyclerview.widget.RecyclerView r19, com.quizlet.quizletandroid.ui.startpage.nav2.Y r20, boolean r21, com.quizlet.quizletandroid.ui.startpage.nav2.model.u r22, int r23) {
        /*
            Method dump skipped, instructions count: 966
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.X5.b(androidx.recyclerview.widget.RecyclerView, com.quizlet.quizletandroid.ui.startpage.nav2.Y, boolean, com.quizlet.quizletandroid.ui.startpage.nav2.model.u, int):void");
    }

    public static final boolean c(RecyclerView recyclerView, int i) {
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        AbstractC1381n0 layoutManager = recyclerView.getLayoutManager();
        Intrinsics.d(layoutManager);
        View viewQ = layoutManager.q(i);
        if (viewQ == null) {
            return false;
        }
        Rect rect = new Rect();
        viewQ.getGlobalVisibleRect(rect);
        return (((double) (rect.width() * rect.height())) * 1.0d) / ((double) (viewQ.getWidth() * viewQ.getHeight())) > 0.1d;
    }
}
