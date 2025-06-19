package androidx.compose.ui.platform;

import android.view.View;
import android.view.translation.ViewTranslationCallback;
import androidx.collection.C0223v;
import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J implements ViewTranslationCallback {
    public static final J a = new J();

    /* JADX WARN: Removed duplicated region for block: B:26:0x007b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onClearTranslation(android.view.View r15) {
        /*
            r14 = this;
            java.lang.String r0 = "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"
            kotlin.jvm.internal.Intrinsics.e(r15, r0)
            androidx.compose.ui.platform.v r15 = (androidx.compose.ui.platform.C0971v) r15
            androidx.compose.ui.contentcapture.c r15 = r15.getContentCaptureManager$ui_release()
            r0 = 1
            r15.g = r0
            androidx.collection.v r15 = r15.b()
            java.lang.Object[] r1 = r15.c
            long[] r15 = r15.a
            int r2 = r15.length
            int r2 = r2 + (-2)
            if (r2 < 0) goto L80
            r3 = 0
            r4 = r3
        L1d:
            r5 = r15[r4]
            long r7 = ~r5
            r9 = 7
            long r7 = r7 << r9
            long r7 = r7 & r5
            r9 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r7 = r7 & r9
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 == 0) goto L7b
            int r7 = r4 - r2
            int r7 = ~r7
            int r7 = r7 >>> 31
            r8 = 8
            int r7 = 8 - r7
            r9 = r3
        L37:
            if (r9 >= r7) goto L79
            r10 = 255(0xff, double:1.26E-321)
            long r10 = r10 & r5
            r12 = 128(0x80, double:6.3E-322)
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 >= 0) goto L75
            int r10 = r4 << 3
            int r10 = r10 + r9
            r10 = r1[r10]
            androidx.compose.ui.platform.P0 r10 = (androidx.compose.ui.platform.P0) r10
            androidx.compose.ui.semantics.o r10 = r10.a
            androidx.compose.ui.semantics.k r10 = r10.d
            androidx.compose.ui.semantics.u r11 = androidx.compose.ui.semantics.r.w
            java.util.LinkedHashMap r10 = r10.a
            java.lang.Object r11 = r10.get(r11)
            r12 = 0
            if (r11 != 0) goto L59
            r11 = r12
        L59:
            if (r11 == 0) goto L75
            androidx.compose.ui.semantics.u r11 = androidx.compose.ui.semantics.j.l
            java.lang.Object r10 = r10.get(r11)
            if (r10 != 0) goto L64
            goto L65
        L64:
            r12 = r10
        L65:
            androidx.compose.ui.semantics.a r12 = (androidx.compose.ui.semantics.a) r12
            if (r12 == 0) goto L75
            kotlin.g r10 = r12.b
            kotlin.jvm.functions.Function0 r10 = (kotlin.jvm.functions.Function0) r10
            if (r10 == 0) goto L75
            java.lang.Object r10 = r10.invoke()
            java.lang.Boolean r10 = (java.lang.Boolean) r10
        L75:
            long r5 = r5 >> r8
            int r9 = r9 + 1
            goto L37
        L79:
            if (r7 != r8) goto L80
        L7b:
            if (r4 == r2) goto L80
            int r4 = r4 + 1
            goto L1d
        L80:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.J.onClearTranslation(android.view.View):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0083  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onHideTranslation(android.view.View r15) {
        /*
            r14 = this;
            java.lang.String r0 = "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"
            kotlin.jvm.internal.Intrinsics.e(r15, r0)
            androidx.compose.ui.platform.v r15 = (androidx.compose.ui.platform.C0971v) r15
            androidx.compose.ui.contentcapture.c r15 = r15.getContentCaptureManager$ui_release()
            r0 = 1
            r15.g = r0
            androidx.collection.v r15 = r15.b()
            java.lang.Object[] r1 = r15.c
            long[] r15 = r15.a
            int r2 = r15.length
            int r2 = r2 + (-2)
            if (r2 < 0) goto L88
            r3 = 0
            r4 = r3
        L1d:
            r5 = r15[r4]
            long r7 = ~r5
            r9 = 7
            long r7 = r7 << r9
            long r7 = r7 & r5
            r9 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r7 = r7 & r9
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 == 0) goto L83
            int r7 = r4 - r2
            int r7 = ~r7
            int r7 = r7 >>> 31
            r8 = 8
            int r7 = 8 - r7
            r9 = r3
        L37:
            if (r9 >= r7) goto L81
            r10 = 255(0xff, double:1.26E-321)
            long r10 = r10 & r5
            r12 = 128(0x80, double:6.3E-322)
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 >= 0) goto L7d
            int r10 = r4 << 3
            int r10 = r10 + r9
            r10 = r1[r10]
            androidx.compose.ui.platform.P0 r10 = (androidx.compose.ui.platform.P0) r10
            androidx.compose.ui.semantics.o r10 = r10.a
            androidx.compose.ui.semantics.k r10 = r10.d
            androidx.compose.ui.semantics.u r11 = androidx.compose.ui.semantics.r.w
            java.util.LinkedHashMap r10 = r10.a
            java.lang.Object r11 = r10.get(r11)
            r12 = 0
            if (r11 != 0) goto L59
            r11 = r12
        L59:
            java.lang.Boolean r13 = java.lang.Boolean.TRUE
            boolean r11 = kotlin.jvm.internal.Intrinsics.b(r11, r13)
            if (r11 == 0) goto L7d
            androidx.compose.ui.semantics.u r11 = androidx.compose.ui.semantics.j.k
            java.lang.Object r10 = r10.get(r11)
            if (r10 != 0) goto L6a
            goto L6b
        L6a:
            r12 = r10
        L6b:
            androidx.compose.ui.semantics.a r12 = (androidx.compose.ui.semantics.a) r12
            if (r12 == 0) goto L7d
            kotlin.g r10 = r12.b
            kotlin.jvm.functions.Function1 r10 = (kotlin.jvm.functions.Function1) r10
            if (r10 == 0) goto L7d
            java.lang.Boolean r11 = java.lang.Boolean.FALSE
            java.lang.Object r10 = r10.invoke(r11)
            java.lang.Boolean r10 = (java.lang.Boolean) r10
        L7d:
            long r5 = r5 >> r8
            int r9 = r9 + 1
            goto L37
        L81:
            if (r7 != r8) goto L88
        L83:
            if (r4 == r2) goto L88
            int r4 = r4 + 1
            goto L1d
        L88:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.J.onHideTranslation(android.view.View):boolean");
    }

    public final boolean onShowTranslation(View view) {
        Function1 function1;
        Intrinsics.e(view, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView");
        androidx.compose.ui.contentcapture.c contentCaptureManager$ui_release = ((C0971v) view).getContentCaptureManager$ui_release();
        contentCaptureManager$ui_release.g = 2;
        C0223v c0223vB = contentCaptureManager$ui_release.b();
        Object[] objArr = c0223vB.c;
        long[] jArr = c0223vB.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return true;
        }
        int i = 0;
        while (true) {
            long j = jArr[i];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i2 = 8 - ((~(i - length)) >>> 31);
                for (int i3 = 0; i3 < i2; i3++) {
                    if ((255 & j) < 128) {
                        androidx.compose.ui.semantics.k kVar = ((P0) objArr[(i << 3) + i3]).a.d;
                        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.w;
                        LinkedHashMap linkedHashMap = kVar.a;
                        Object obj = linkedHashMap.get(uVar);
                        if (obj == null) {
                            obj = null;
                        }
                        if (Intrinsics.b(obj, Boolean.FALSE)) {
                            Object obj2 = linkedHashMap.get(androidx.compose.ui.semantics.j.k);
                            androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) (obj2 != null ? obj2 : null);
                            if (aVar != null && (function1 = (Function1) aVar.b) != null) {
                            }
                        }
                    }
                    j >>= 8;
                }
                if (i2 != 8) {
                    return true;
                }
            }
            if (i == length) {
                return true;
            }
            i++;
        }
    }
}
