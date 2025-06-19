package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class F4 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:218:0x04a9  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x04ab  */
    /* JADX WARN: Removed duplicated region for block: B:225:0x04b9  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x04f0  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x0524  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x0526  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x052f  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x056f  */
    /* JADX WARN: Removed duplicated region for block: B:251:0x0571  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x057a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.folders.data.U r44, final com.quizlet.features.folders.data.W0 r45, final com.quizlet.features.folders.data.P0 r46, final com.quizlet.features.folders.data.InterfaceC4318y0 r47, com.quizlet.features.folders.data.T0 r48, final androidx.compose.ui.n r49, final com.quizlet.features.folders.menu.m r50, final com.quizlet.features.folders.menu.u r51, androidx.compose.ui.focus.h r52, final com.quizlet.assembly.compose.modals.x r53, final com.quizlet.assembly.compose.modals.x r54, final com.quizlet.assembly.compose.modals.x r55, final com.quizlet.assembly.compose.modals.x r56, final com.quizlet.assembly.compose.modals.x r57, com.quizlet.assembly.compose.modals.x r58, final androidx.compose.material3.O3 r59, int r60, final kotlin.jvm.functions.Function0 r61, kotlin.jvm.functions.Function1 r62, androidx.compose.runtime.InterfaceC0806l r63, final int r64, final int r65) {
        /*
            Method dump skipped, instructions count: 1485
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.F4.a(com.quizlet.features.folders.data.U, com.quizlet.features.folders.data.W0, com.quizlet.features.folders.data.P0, com.quizlet.features.folders.data.y0, com.quizlet.features.folders.data.T0, androidx.compose.ui.n, com.quizlet.features.folders.menu.m, com.quizlet.features.folders.menu.u, androidx.compose.ui.focus.h, com.quizlet.assembly.compose.modals.x, com.quizlet.assembly.compose.modals.x, com.quizlet.assembly.compose.modals.x, com.quizlet.assembly.compose.modals.x, com.quizlet.assembly.compose.modals.x, com.quizlet.assembly.compose.modals.x, androidx.compose.material3.O3, int, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(androidx.collection.I i, Object obj, Object obj2) {
        int iE = i.e(obj);
        boolean z = iE < 0;
        Object obj3 = z ? null : i.c[iE];
        if (obj3 != null) {
            if (obj3 instanceof androidx.collection.J) {
                ((androidx.collection.J) obj3).a(obj2);
            } else if (obj3 != obj2) {
                androidx.collection.J j = new androidx.collection.J();
                j.a(obj3);
                j.a(obj2);
                obj2 = j;
            }
            obj2 = obj3;
        }
        if (!z) {
            i.c[iE] = obj2;
            return;
        }
        int i2 = ~iE;
        i.b[i2] = obj;
        i.c[i2] = obj2;
    }

    public static androidx.collection.I c() {
        long[] jArr = androidx.collection.S.a;
        return new androidx.collection.I();
    }

    public static final boolean d(androidx.collection.I i, Object obj, Object obj2) {
        Object objF = i.f(obj);
        if (objF == null) {
            return false;
        }
        if (!(objF instanceof androidx.collection.J)) {
            if (!objF.equals(obj2)) {
                return false;
            }
            i.h(obj);
            return true;
        }
        androidx.collection.J j = (androidx.collection.J) objF;
        boolean zJ = j.j(obj2);
        if (zJ && j.g()) {
            i.h(obj);
        }
        return zJ;
    }

    public static final void e(androidx.collection.I i, Object obj) {
        boolean zG;
        long[] jArr = i.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            long j = jArr[i2];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i3 = 8 - ((~(i2 - length)) >>> 31);
                for (int i4 = 0; i4 < i3; i4++) {
                    if ((255 & j) < 128) {
                        int i5 = (i2 << 3) + i4;
                        Object obj2 = i.b[i5];
                        Object obj3 = i.c[i5];
                        if (obj3 instanceof androidx.collection.J) {
                            Intrinsics.e(obj3, "null cannot be cast to non-null type androidx.collection.MutableScatterSet<Scope of androidx.compose.runtime.collection.ScopeMap>");
                            androidx.collection.J j2 = (androidx.collection.J) obj3;
                            j2.j(obj);
                            zG = j2.g();
                        } else {
                            zG = obj3 == obj;
                        }
                        if (zG) {
                            i.i(i5);
                        }
                    }
                    j >>= 8;
                }
                if (i3 != 8) {
                    return;
                }
            }
            if (i2 == length) {
                return;
            } else {
                i2++;
            }
        }
    }
}
