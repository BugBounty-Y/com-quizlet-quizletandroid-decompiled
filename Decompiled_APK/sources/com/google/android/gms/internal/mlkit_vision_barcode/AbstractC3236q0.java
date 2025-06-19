package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.material.C0560c;
import androidx.compose.material.C0575s;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import java.util.Set;
import kotlin.Unit;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.q0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3236q0 {
    /* JADX WARN: Removed duplicated region for block: B:27:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x01d6  */
    /* JADX WARN: Removed duplicated region for block: B:72:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final int r24, final int r25, final int r26, androidx.compose.ui.q r27, boolean r28, final kotlin.jvm.functions.Function0 r29, final kotlin.jvm.functions.Function0 r30, androidx.compose.runtime.InterfaceC0806l r31, final int r32, final int r33) {
        /*
            Method dump skipped, instructions count: 484
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3236q0.a(int, int, int, androidx.compose.ui.q, boolean, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(kotlin.jvm.functions.Function0 r4, kotlin.jvm.functions.Function2 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof androidx.compose.material.C0561d
            if (r0 == 0) goto L13
            r0 = r6
            androidx.compose.material.d r0 = (androidx.compose.material.C0561d) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            androidx.compose.material.d r0 = new androidx.compose.material.d
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: androidx.compose.material.AnchoredDragFinishedSignal -> L41
            goto L41
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.material.h r6 = new androidx.compose.material.h     // Catch: androidx.compose.material.AnchoredDragFinishedSignal -> L41
            r2 = 0
            r6.<init>(r4, r5, r2)     // Catch: androidx.compose.material.AnchoredDragFinishedSignal -> L41
            r0.k = r3     // Catch: androidx.compose.material.AnchoredDragFinishedSignal -> L41
            java.lang.Object r4 = kotlinx.coroutines.E.m(r6, r0)     // Catch: androidx.compose.material.AnchoredDragFinishedSignal -> L41
            if (r4 != r1) goto L41
            return r1
        L41:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3236q0.b(kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object c(C0575s c0575s, Object obj, float f, kotlin.coroutines.jvm.internal.c cVar) {
        Object objB = c0575s.b(obj, androidx.compose.foundation.u0.a, new C0560c(c0575s, f, null, 0), cVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    public static final int d(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1684870419);
        androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
        Set set = androidx.compose.material3.windowsizeclass.c.b;
        int i = bVarG.a == 0 ? 1 : 2;
        c0814p.p(false);
        return i;
    }
}
