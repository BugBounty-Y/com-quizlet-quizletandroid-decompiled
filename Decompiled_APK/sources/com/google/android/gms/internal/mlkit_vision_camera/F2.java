package com.google.android.gms.internal.mlkit_vision_camera;

import android.net.NetworkRequest;
import android.os.Build;
import android.text.Spannable;
import androidx.compose.foundation.layout.InterfaceC0390i;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.AztecTaskListSpan;
import org.wordpress.aztec.spans.C5164l;

/* loaded from: classes2.dex */
public abstract class F2 {
    /* JADX WARN: Removed duplicated region for block: B:56:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0188  */
    /* JADX WARN: Removed duplicated region for block: B:97:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.foundation.layout.InterfaceC0390i r21, com.quizlet.features.infra.models.a r22, java.lang.String r23, androidx.compose.ui.q r24, long r25, androidx.compose.runtime.internal.d r27, kotlin.jvm.functions.Function0 r28, androidx.compose.runtime.InterfaceC0806l r29, int r30, int r31) {
        /*
            Method dump skipped, instructions count: 412
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.F2.a(androidx.compose.foundation.layout.i, com.quizlet.features.infra.models.a, java.lang.String, androidx.compose.ui.q, long, androidx.compose.runtime.internal.d, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(InterfaceC0390i horizontalArrangement, com.quizlet.features.infra.models.a aVar, String str, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        androidx.compose.foundation.layout.I0 i0;
        float f;
        boolean z;
        boolean z2;
        androidx.compose.ui.n nVar3;
        String str2;
        Intrinsics.checkNotNullParameter(horizontalArrangement, "horizontalArrangement");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(702715315);
        int i3 = i | (c0814p.f(horizontalArrangement) ? 4 : 2) | (c0814p.f(aVar) ? 32 : 16) | (c0814p.f(str) ? 256 : 128) | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
        } else {
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar4, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(horizontalArrangement, hVar, c0814p, (((((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 384) >> 3) & 14) | 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.foundation.layout.I0 i02 = androidx.compose.foundation.layout.I0.a;
            c0814p.X(2135468734);
            if (aVar == null || (str2 = aVar.a) == null || StringsKt.O(str2)) {
                i2 = i3;
                nVar2 = nVar4;
                i0 = i02;
                f = 1.0f;
                z = true;
            } else {
                i2 = i3;
                z = true;
                nVar2 = nVar4;
                i0 = i02;
                f = 1.0f;
                AbstractC3164i0.c(aVar.c, aVar.a, aVar.d, aVar.b, i02.a(androidx.compose.ui.platform.N.G(nVar4, "ButtonText"), 1.0f, true), null, 0L, 0, 0, null, null, c0814p, 0, 0, 2016);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.X(2135482936);
            if (str == null || StringsKt.O(str)) {
                z2 = z;
            } else {
                z2 = z;
                r3.a(str, null, i0.a(androidx.compose.ui.platform.N.G(nVar2, "ButtonImage"), f, z), null, null, null, c0814p, ((i2 >> 6) & 14) | 48, 2040);
            }
            c0814p.p(false);
            c0814p.p(z2);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) horizontalArrangement, (Object) aVar, (Object) str, nVar3, i, 23);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0183  */
    /* JADX WARN: Removed duplicated region for block: B:85:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(com.quizlet.features.questiontypes.composables.a r14, androidx.compose.ui.q r15, com.quizlet.features.infra.models.a r16, java.lang.String r17, kotlin.jvm.functions.Function0 r18, androidx.compose.runtime.InterfaceC0806l r19, int r20, int r21) {
        /*
            Method dump skipped, instructions count: 403
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.F2.c(com.quizlet.features.questiontypes.composables.a, androidx.compose.ui.q, com.quizlet.features.infra.models.a, java.lang.String, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final int[] d(NetworkRequest request) {
        Intrinsics.checkNotNullParameter(request, "<this>");
        if (Build.VERSION.SDK_INT >= 31) {
            Intrinsics.checkNotNullParameter(request, "request");
            int[] capabilities = request.getCapabilities();
            Intrinsics.checkNotNullExpressionValue(capabilities, "request.capabilities");
            return capabilities;
        }
        int[] iArr = {17, 5, 2, 10, 29, 19, 3, 32, 7, 4, 12, 23, 0, 33, 20, 11, 13, 18, 21, 15, 35, 34, 8, 1, 25, 14, 16, 6, 9};
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < 29; i++) {
            int i2 = iArr[i];
            Intrinsics.checkNotNullParameter(request, "request");
            if (request.hasCapability(i2)) {
                arrayList.add(Integer.valueOf(i2));
            }
        }
        return CollectionsKt.v0(arrayList);
    }

    public static final int[] e(NetworkRequest request) {
        Intrinsics.checkNotNullParameter(request, "<this>");
        if (Build.VERSION.SDK_INT >= 31) {
            Intrinsics.checkNotNullParameter(request, "request");
            int[] transportTypes = request.getTransportTypes();
            Intrinsics.checkNotNullExpressionValue(transportTypes, "request.transportTypes");
            return transportTypes;
        }
        int[] iArr = {2, 0, 3, 6, 9, 8, 4, 1, 5};
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < 9; i++) {
            int i2 = iArr[i];
            Intrinsics.checkNotNullParameter(request, "request");
            if (request.hasTransport(i2)) {
                arrayList.add(Integer.valueOf(i2));
            }
        }
        return CollectionsKt.v0(arrayList);
    }

    public static void f(Spannable text, int i, int i2, int i3, EnumC5145a alignmentRendering, org.wordpress.aztec.formatting.d listItemStyle) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        Object[] spans = text.getSpans(i, i2, AztecTaskListSpan.class);
        boolean z = spans == null || spans.length == 0;
        C5164l c5164lB = N2.b(i3, alignmentRendering, null, listItemStyle, 4);
        if (!z) {
            c5164lB.b.d("checked", "false");
        }
        Unit unit = Unit.a;
        E2.b(text, c5164lB, i, i2);
    }
}
