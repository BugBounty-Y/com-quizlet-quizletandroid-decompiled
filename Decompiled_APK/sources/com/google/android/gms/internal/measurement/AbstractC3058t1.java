package com.google.android.gms.internal.measurement;

import android.content.Context;
import android.os.UserManager;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.t1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3058t1 {
    public static UserManager a = null;
    public static volatile boolean b = false;

    /* JADX WARN: Removed duplicated region for block: B:107:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x020e  */
    /* JADX WARN: Removed duplicated region for block: B:113:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x010c  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x015b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final com.quizlet.data.model.C4114c r29, androidx.compose.ui.q r30, float r31, kotlin.jvm.functions.Function0 r32, androidx.compose.runtime.InterfaceC0806l r33, final int r34, final int r35) {
        /*
            Method dump skipped, instructions count: 536
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.AbstractC3058t1.a(com.quizlet.data.model.c, androidx.compose.ui.q, float, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final ArrayList b(Context context, List list) {
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        for (Object objA : list) {
            if (objA instanceof com.quizlet.qutils.string.g) {
                objA = ((com.quizlet.qutils.string.g) objA).a(context);
            }
            arrayList.add(objA);
        }
        return arrayList;
    }

    public static androidx.concurrent.futures.l c(List list, androidx.camera.core.impl.utils.executor.k kVar, androidx.camera.core.impl.utils.executor.e eVar) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(androidx.camera.core.impl.utils.futures.i.d(((androidx.camera.core.impl.J) it2.next()).c()));
        }
        return Y5.b(new androidx.camera.camera2.internal.T(Y5.b(new androidx.camera.core.impl.utils.futures.e(new androidx.camera.core.impl.utils.futures.l(new ArrayList(arrayList), false, com.google.android.gms.internal.mlkit_vision_barcode.T.a()), eVar, 5000L, 0)), kVar, list, 1));
    }
}
