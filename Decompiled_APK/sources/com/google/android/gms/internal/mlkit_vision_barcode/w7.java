package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.util.SizeF;
import android.widget.RemoteViews;
import androidx.glance.appwidget.C1160b;
import androidx.glance.appwidget.C1179k0;
import androidx.glance.appwidget.C1185n0;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class w7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(RemoteViews remoteViews, androidx.glance.appwidget.N0 n0, C1179k0 c1179k0, ArrayList arrayList) {
        int i = 0;
        for (Object obj : CollectionsKt.p0(arrayList, 10)) {
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            c(remoteViews, n0.b(c1179k0, i), (androidx.glance.k) obj);
            i = i2;
        }
    }

    public static final int b(androidx.glance.layout.c cVar) {
        int i = cVar.a;
        int i2 = 8388611;
        if (i != 0) {
            if (i == 2) {
                i2 = 8388613;
            } else if (i == 1) {
                i2 = 1;
            } else {
                Log.w("GlanceAppWidget", "Unknown horizontal alignment: " + ((Object) androidx.glance.layout.a.b(i)));
            }
        }
        int i3 = cVar.b;
        int i4 = 48;
        if (i3 != 0) {
            if (i3 == 2) {
                i4 = 80;
            } else if (i3 == 1) {
                i4 = 16;
            } else {
                Log.w("GlanceAppWidget", "Unknown vertical alignment: " + ((Object) androidx.glance.layout.b.b(i3)));
            }
        }
        return i2 | i4;
    }

    /* JADX WARN: Removed duplicated region for block: B:230:0x0566  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(android.widget.RemoteViews r30, androidx.glance.appwidget.N0 r31, androidx.glance.k r32) {
        /*
            Method dump skipped, instructions count: 1713
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.w7.c(android.widget.RemoteViews, androidx.glance.appwidget.N0, androidx.glance.k):void");
    }

    public static final RemoteViews d(androidx.glance.appwidget.N0 n0, List list, int i) {
        if (list == null || !list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                if (!(((androidx.glance.k) it2.next()) instanceof androidx.glance.appwidget.E)) {
                    androidx.glance.k kVar = (androidx.glance.k) CollectionsKt.j0(list);
                    androidx.glance.appwidget.A0 a0A = androidx.glance.appwidget.r0.a(n0, kVar.a(), i);
                    androidx.glance.appwidget.N0 n0A = androidx.glance.appwidget.N0.a(n0.b(a0A.b, 0), 0, new AtomicInteger(1), null, new AtomicBoolean(false), 0L, 0, null, 32447);
                    RemoteViews remoteViews = a0A.a;
                    c(remoteViews, n0A, kVar);
                    return remoteViews;
                }
            }
        }
        Object objL = CollectionsKt.L(list);
        Intrinsics.e(objL, "null cannot be cast to non-null type androidx.glance.appwidget.EmittableSizeBox");
        androidx.glance.appwidget.J0 j0 = ((androidx.glance.appwidget.E) objL).e;
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            androidx.glance.k kVar2 = (androidx.glance.k) it3.next();
            Intrinsics.e(kVar2, "null cannot be cast to non-null type androidx.glance.appwidget.EmittableSizeBox");
            long j = ((androidx.glance.appwidget.E) kVar2).d;
            androidx.glance.appwidget.A0 a0A2 = androidx.glance.appwidget.r0.a(n0, kVar2.a(), i);
            androidx.glance.appwidget.N0 n0A2 = androidx.glance.appwidget.N0.a(n0.b(a0A2.b, 0), 0, new AtomicInteger(1), null, new AtomicBoolean(false), j, 0, null, 31935);
            RemoteViews remoteViews2 = a0A2.a;
            c(remoteViews2, n0A2, kVar2);
            arrayList.add(new Pair(new SizeF(androidx.compose.ui.unit.g.b(j), androidx.compose.ui.unit.g.a(j)), remoteViews2));
        }
        if (j0 instanceof androidx.glance.appwidget.I0) {
            return (RemoteViews) ((Pair) CollectionsKt.j0(arrayList)).b;
        }
        if (!Intrinsics.b(j0, androidx.glance.appwidget.H0.a)) {
            throw new NoWhenBranchMatchedException();
        }
        if (Build.VERSION.SDK_INT >= 31) {
            return C1160b.a.a(kotlin.collections.V.k(arrayList));
        }
        if (arrayList.size() != 1 && arrayList.size() != 2) {
            throw new IllegalArgumentException("unsupported views size");
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it4 = arrayList.iterator();
        while (it4.hasNext()) {
            arrayList2.add((RemoteViews) ((Pair) it4.next()).b);
        }
        int size = arrayList2.size();
        if (size == 1) {
            return (RemoteViews) arrayList2.get(0);
        }
        if (size == 2) {
            return new RemoteViews((RemoteViews) arrayList2.get(0), (RemoteViews) arrayList2.get(1));
        }
        throw new IllegalArgumentException("There must be between 1 and 2 views.");
    }

    public static final RemoteViews e(Context context, int i, androidx.glance.appwidget.B0 b0, C1185n0 c1185n0, int i2, ComponentName componentName) {
        return d(new androidx.glance.appwidget.N0(context, i, context.getResources().getConfiguration().getLayoutDirection() == 1, c1185n0, -1, false, new AtomicInteger(1), new C1179k0(0, 0, null, 7), new AtomicBoolean(false), 9205357640488583168L, -1, false, null, componentName), b0.c, i2);
    }
}
