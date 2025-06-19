package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.internal.client.C1597h0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y {
    public static final /* synthetic */ int a = 0;

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0040 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r9v6, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x003e -> B:18:0x0041). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.compose.ui.input.pointer.z r8, kotlin.coroutines.jvm.internal.a r9) {
        /*
            boolean r0 = r9 instanceof androidx.compose.foundation.contextmenu.d
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.foundation.contextmenu.d r0 = (androidx.compose.foundation.contextmenu.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.foundation.contextmenu.d r0 = new androidx.compose.foundation.contextmenu.d
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.ui.input.pointer.z r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L41
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
        L34:
            r0.j = r8
            r0.l = r3
            androidx.compose.ui.input.pointer.g r9 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r9 = r8.c(r9, r0)
            if (r9 != r1) goto L41
            return r1
        L41:
            androidx.compose.ui.input.pointer.f r9 = (androidx.compose.ui.input.pointer.f) r9
            int r2 = r9.c
            r2 = r2 & 66
            if (r2 == 0) goto L34
            java.lang.Object r9 = r9.a
            int r2 = r9.size()
            r4 = 0
            r5 = r4
        L51:
            if (r5 >= r2) goto L6a
            java.lang.Object r6 = r9.get(r5)
            androidx.compose.ui.input.pointer.n r6 = (androidx.compose.ui.input.pointer.n) r6
            boolean r7 = r6.b()
            if (r7 != 0) goto L34
            boolean r7 = r6.h
            if (r7 != 0) goto L34
            boolean r6 = r6.d
            if (r6 == 0) goto L34
            int r5 = r5 + 1
            goto L51
        L6a:
            java.lang.Object r8 = r9.get(r4)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.Y.a(androidx.compose.ui.input.pointer.z, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g b(io.reactivex.rxjava3.internal.operators.single.g gVar, String errorMessage) {
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        Intrinsics.checkNotNullParameter(errorMessage, "errorMessage");
        io.reactivex.rxjava3.internal.operators.single.g gVar2 = new io.reactivex.rxjava3.internal.operators.single.g(gVar, new C1597h0(errorMessage), 2);
        Intrinsics.checkNotNullExpressionValue(gVar2, "onErrorResumeNext(...)");
        return gVar2;
    }
}
