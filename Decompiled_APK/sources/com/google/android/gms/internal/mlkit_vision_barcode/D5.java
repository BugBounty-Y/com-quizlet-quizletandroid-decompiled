package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Intent;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public abstract class D5 {
    /* JADX WARN: Removed duplicated region for block: B:40:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:92:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final kotlinx.collections.immutable.b r20, final androidx.compose.foundation.pager.C0466e r21, androidx.compose.ui.n r22, long r23, boolean r25, kotlin.jvm.functions.Function1 r26, androidx.compose.runtime.InterfaceC0806l r27, final int r28, final int r29) {
        /*
            Method dump skipped, instructions count: 371
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.D5.a(kotlinx.collections.immutable.b, androidx.compose.foundation.pager.e, androidx.compose.ui.n, long, boolean, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final C0995g b(androidx.compose.ui.text.input.A a) {
        C0995g c0995g = a.a;
        c0995g.getClass();
        long j = a.b;
        return c0995g.subSequence(androidx.compose.ui.text.K.e(j), androidx.compose.ui.text.K.d(j));
    }

    public static final C0995g c(androidx.compose.ui.text.input.A a, int i) {
        C0995g c0995g = a.a;
        long j = a.b;
        return c0995g.subSequence(androidx.compose.ui.text.K.d(j), Math.min(androidx.compose.ui.text.K.d(j) + i, a.a.a.length()));
    }

    public static final C0995g d(androidx.compose.ui.text.input.A a, int i) {
        C0995g c0995g = a.a;
        long j = a.b;
        return c0995g.subSequence(Math.max(0, androidx.compose.ui.text.K.e(j) - i), androidx.compose.ui.text.K.e(j));
    }

    public static final Function0 e(String[] strArr, Function1 function1, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1291602899);
        androidx.compose.runtime.V v = C0804k.a;
        androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
        c0814p.X(1545593571);
        boolean zF = c0814p.f(function1);
        Object objI = c0814p.I();
        if (zF || objI == v) {
            objI = new androidx.navigation.compose.B(21, function1);
            c0814p.i0(objI);
        }
        c0814p.p(false);
        androidx.activity.compose.o oVarF = androidx.work.P.f(bVar, (Function1) objI, c0814p);
        Intent intent = new Intent("android.intent.action.OPEN_DOCUMENT");
        intent.addFlags(1);
        intent.addCategory("android.intent.category.OPENABLE");
        intent.setType("*/*");
        intent.putExtra("android.intent.extra.MIME_TYPES", strArr);
        c0814p.X(1545624212);
        boolean zH = c0814p.h(oVarF) | c0814p.h(intent);
        Object objI2 = c0814p.I();
        if (zH || objI2 == v) {
            objI2 = new com.quizlet.features.infra.document.a(oVarF, intent, 0);
            c0814p.i0(objI2);
        }
        Function0 function0 = (Function0) objI2;
        c0814p.p(false);
        c0814p.p(false);
        return function0;
    }
}
