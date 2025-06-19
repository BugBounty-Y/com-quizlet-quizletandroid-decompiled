package androidx.glance.appwidget;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.widget.RemoteViews;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;

/* loaded from: classes.dex */
public abstract class r0 {
    public static final Object a = kotlin.collections.V.f(new Pair(u0.d, Integer.valueOf(R.layout.glance_text)), new Pair(u0.e, Integer.valueOf(R.layout.glance_list)), new Pair(u0.f, Integer.valueOf(R.layout.glance_check_box)), new Pair(u0.g, Integer.valueOf(R.layout.glance_check_box_backport)), new Pair(u0.h, Integer.valueOf(R.layout.glance_button)), new Pair(u0.r, Integer.valueOf(R.layout.glance_swtch)), new Pair(u0.s, Integer.valueOf(R.layout.glance_swtch_backport)), new Pair(u0.i, Integer.valueOf(R.layout.glance_frame)), new Pair(u0.t, Integer.valueOf(R.layout.glance_image_crop)), new Pair(u0.w, Integer.valueOf(R.layout.glance_image_crop_decorative)), new Pair(u0.u, Integer.valueOf(R.layout.glance_image_fit)), new Pair(u0.x, Integer.valueOf(R.layout.glance_image_fit_decorative)), new Pair(u0.v, Integer.valueOf(R.layout.glance_image_fill_bounds)), new Pair(u0.y, Integer.valueOf(R.layout.glance_image_fill_bounds_decorative)), new Pair(u0.j, Integer.valueOf(R.layout.glance_linear_progress_indicator)), new Pair(u0.k, Integer.valueOf(R.layout.glance_circular_progress_indicator)), new Pair(u0.l, Integer.valueOf(R.layout.glance_vertical_grid_one_column)), new Pair(u0.m, Integer.valueOf(R.layout.glance_vertical_grid_two_columns)), new Pair(u0.n, Integer.valueOf(R.layout.glance_vertical_grid_three_columns)), new Pair(u0.o, Integer.valueOf(R.layout.glance_vertical_grid_four_columns)), new Pair(u0.p, Integer.valueOf(R.layout.glance_vertical_grid_five_columns)), new Pair(u0.q, Integer.valueOf(R.layout.glance_vertical_grid_auto_fit)), new Pair(u0.z, Integer.valueOf(R.layout.glance_radio_button)), new Pair(u0.A, Integer.valueOf(R.layout.glance_radio_button_backport)));
    public static final int b;
    public static final int c;

    /* JADX WARN: Type inference failed for: r0v26, types: [java.lang.Object, java.util.Map] */
    static {
        int size = I.f.size();
        b = size;
        c = Build.VERSION.SDK_INT >= 31 ? I.h : I.h / size;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.Map] */
    public static final A0 a(N0 n0, androidx.glance.p pVar, int i) {
        int i2 = Build.VERSION.SDK_INT;
        Context context = n0.a;
        if (i2 >= 31) {
            int i3 = I.h;
            if (i >= i3) {
                throw new IllegalArgumentException(androidx.compose.animation.d0.p("Index of the root view cannot be more than ", i3, ", currently ", i).toString());
            }
            K0 k0 = new K0(1, 1);
            RemoteViews remoteViews = new RemoteViews(context.getPackageName(), I.g + i);
            androidx.glance.layout.t tVar = (androidx.glance.layout.t) pVar.a(null, q0.d);
            if (tVar != null) {
                AbstractC3234p7.g(remoteViews, tVar, R.id.rootView);
            }
            androidx.glance.layout.m mVar = (androidx.glance.layout.m) pVar.a(null, q0.e);
            if (mVar != null) {
                AbstractC3234p7.f(remoteViews, mVar, R.id.rootView);
            }
            if (i2 >= 33) {
                remoteViews.removeAllViews(R.id.rootView);
            }
            return new A0(remoteViews, new C1179k0(R.id.rootView, 0, i2 >= 33 ? kotlin.collections.V.c() : kotlin.collections.U.b(new Pair(0, kotlin.collections.U.b(new Pair(k0, Integer.valueOf(R.id.rootStubId))))), 2));
        }
        int i4 = b * i;
        int i5 = I.h;
        if (i4 >= i5) {
            throw new IllegalArgumentException(("Index of the root view cannot be more than " + (i5 / 4) + ", currently " + i).toString());
        }
        androidx.glance.layout.t tVar2 = (androidx.glance.layout.t) pVar.a(null, q0.b);
        androidx.glance.unit.g gVar = androidx.glance.unit.f.a;
        androidx.glance.unit.g gVar2 = tVar2 != null ? tVar2.a : gVar;
        androidx.glance.layout.m mVar2 = (androidx.glance.layout.m) pVar.a(null, q0.c);
        if (mVar2 != null) {
            gVar = mVar2.a;
        }
        androidx.glance.unit.e eVar = androidx.glance.unit.e.a;
        int i6 = gVar2.equals(eVar) ? 4 : 1;
        int i7 = gVar.equals(eVar) ? 4 : 1;
        K0 k02 = new K0(i6 == 2 ? 1 : i6, i7 != 2 ? i7 : 1);
        Integer num = (Integer) I.f.get(k02);
        if (num != null) {
            return new A0(new RemoteViews(context.getPackageName(), i4 + I.g + num.intValue()), new C1179k0(0, 0, kotlin.collections.U.b(new Pair(0, kotlin.collections.U.b(new Pair(k02, Integer.valueOf(R.id.rootStubId))))), 3));
        }
        throw new IllegalStateException("Cannot find root element for size [" + androidx.compose.ui.node.B.x(i6) + ", " + androidx.compose.ui.node.B.x(i7) + ']');
    }

    public static final C1179k0 b(RemoteViews remoteViews, N0 n0, u0 u0Var, int i, androidx.glance.p pVar, androidx.glance.layout.a aVar, androidx.glance.layout.b bVar) {
        int iIntValue;
        if (i > 10) {
            Log.e("GlanceAppWidget", "Truncated " + u0Var + " container from " + i + " to 10 elements", new IllegalArgumentException(u0Var + " container cannot have more than 10 elements"));
        }
        int i2 = i <= 10 ? i : 10;
        Integer numF = f(u0Var, pVar);
        if (numF != null) {
            iIntValue = numF.intValue();
        } else {
            C1219w c1219w = (C1219w) I.a.get(new C1220x(u0Var, i2, aVar, bVar));
            Integer numValueOf = c1219w != null ? Integer.valueOf(c1219w.a) : null;
            if (numValueOf == null) {
                throw new IllegalArgumentException("Cannot find container " + u0Var + " with " + i + " children");
            }
            iIntValue = numValueOf.intValue();
        }
        Map map = (Map) I.b.get(u0Var);
        if (map == null) {
            throw new IllegalArgumentException("Cannot find generated children for " + u0Var);
        }
        C1179k0 c1179k0D = d(remoteViews, n0, iIntValue, pVar);
        int i3 = c1179k0D.b;
        int i4 = c1179k0D.a;
        C1179k0 c1179k0 = new C1179k0(i4, i3, map);
        if (Build.VERSION.SDK_INT >= 33) {
            remoteViews.removeAllViews(i4);
        }
        return c1179k0;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Map] */
    public static final C1179k0 c(RemoteViews remoteViews, N0 n0, u0 u0Var, androidx.glance.p pVar) {
        Integer numF = f(u0Var, pVar);
        if (numF != null || (numF = (Integer) a.get(u0Var)) != null) {
            return d(remoteViews, n0, numF.intValue(), pVar);
        }
        throw new IllegalArgumentException("Cannot use `insertView` with a container like " + u0Var);
    }

    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.Object, java.util.Map] */
    public static final C1179k0 d(RemoteViews remoteViews, N0 n0, int i, androidx.glance.p pVar) {
        Integer numValueOf;
        androidx.glance.layout.t tVar = (androidx.glance.layout.t) pVar.a(null, q0.f);
        androidx.glance.unit.g gVar = androidx.glance.unit.f.a;
        androidx.glance.unit.g gVar2 = tVar != null ? tVar.a : gVar;
        androidx.glance.layout.m mVar = (androidx.glance.layout.m) pVar.a(null, q0.g);
        if (mVar != null) {
            gVar = mVar.a;
        }
        if (pVar.b()) {
            numValueOf = null;
        } else {
            if (n0.i.getAndSet(true)) {
                throw new IllegalStateException("At most one view can be set as AppWidgetBackground.");
            }
            numValueOf = Integer.valueOf(android.R.id.background);
        }
        int i2 = Build.VERSION.SDK_INT;
        int i3 = n0.e;
        if (i2 >= 33) {
            int iIntValue = numValueOf != null ? numValueOf.intValue() : n0.g.incrementAndGet();
            RemoteViews remoteViewsA = p0.a.a(n0.a.getPackageName(), i, iIntValue);
            int i4 = n0.h.a;
            if (i2 >= 31) {
                C0.a.a(remoteViews, i4, remoteViewsA, i3);
            } else {
                remoteViews.addView(i4, remoteViewsA);
            }
            return new C1179k0(iIntValue, 0, null, 6);
        }
        if (i2 >= 31) {
            androidx.glance.unit.d dVar = androidx.glance.unit.d.a;
            return new C1179k0(x7.a(remoteViews, n0, e(remoteViews, n0, i3, gVar2.equals(dVar) ? 3 : 1, gVar.equals(dVar) ? 3 : 1), i, numValueOf), 0, null, 6);
        }
        int iG = g(gVar2);
        int iG2 = g(gVar);
        int iE = e(remoteViews, n0, i3, iG, iG2);
        if (iG != 2 && iG2 != 2) {
            return new C1179k0(x7.a(remoteViews, n0, iE, i, numValueOf), 0, null, 6);
        }
        C1187o0 c1187o0 = (C1187o0) I.e.get(new K0(iG, iG2));
        if (c1187o0 != null) {
            return new C1179k0(x7.a(remoteViews, n0, R.id.glanceViewStub, i, numValueOf), x7.a(remoteViews, n0, iE, c1187o0.a, null), null, 4);
        }
        throw new IllegalArgumentException("Could not find complex layout for width=" + androidx.compose.ui.node.B.x(iG) + ", height=" + androidx.compose.ui.node.B.x(iG2));
    }

    public static final int e(RemoteViews remoteViews, N0 n0, int i, int i2, int i3) {
        K0 k0 = new K0(i2 == 2 ? 1 : i2, i3 != 2 ? i3 : 1);
        Map map = (Map) n0.h.c.get(Integer.valueOf(i));
        if (map == null) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(i, "Parent doesn't have child position "));
        }
        Integer num = (Integer) map.get(k0);
        if (num == null) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "No child for position ", " and size ");
            sbV.append(androidx.compose.ui.node.B.x(i2));
            sbV.append(" x ");
            sbV.append(androidx.compose.ui.node.B.x(i3));
            throw new IllegalStateException(sbV.toString());
        }
        int iIntValue = num.intValue();
        Collection collectionValues = map.values();
        ArrayList arrayList = new ArrayList();
        for (Object obj : collectionValues) {
            if (((Number) obj).intValue() != iIntValue) {
                arrayList.add(obj);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            x7.a(remoteViews, n0, ((Number) it2.next()).intValue(), R.layout.glance_deleted_view, Integer.valueOf(R.id.deletedViewId));
        }
        return iIntValue;
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.lang.Object, java.util.Map] */
    public static final Integer f(u0 u0Var, androidx.glance.p pVar) {
        if (Build.VERSION.SDK_INT >= 33) {
            C1158a c1158a = (C1158a) pVar.a(null, q0.h);
            androidx.glance.layout.t tVar = (androidx.glance.layout.t) pVar.a(null, q0.i);
            androidx.glance.unit.d dVar = androidx.glance.unit.d.a;
            boolean zEquals = tVar != null ? tVar.a.equals(dVar) : false;
            androidx.glance.layout.m mVar = (androidx.glance.layout.m) pVar.a(null, q0.j);
            boolean zEquals2 = mVar != null ? mVar.a.equals(dVar) : false;
            if (c1158a != null) {
                ?? r1 = I.c;
                androidx.glance.layout.c cVar = c1158a.a;
                C1187o0 c1187o0 = (C1187o0) r1.get(new C1215s(u0Var, cVar.a, cVar.b));
                if (c1187o0 != null) {
                    return Integer.valueOf(c1187o0.a);
                }
                throw new IllegalArgumentException("Cannot find " + u0Var + " with alignment " + cVar);
            }
            if (zEquals || zEquals2) {
                C1187o0 c1187o02 = (C1187o0) I.d.get(new D0(u0Var, zEquals, zEquals2));
                if (c1187o02 != null) {
                    return Integer.valueOf(c1187o02.a);
                }
                throw new IllegalArgumentException("Cannot find " + u0Var + " with defaultWeight set");
            }
        }
        return null;
    }

    public static final int g(androidx.glance.unit.g gVar) {
        if (gVar instanceof androidx.glance.unit.f) {
            return 1;
        }
        if (gVar instanceof androidx.glance.unit.d) {
            return 3;
        }
        if (gVar instanceof androidx.glance.unit.e) {
            return 4;
        }
        if (gVar instanceof androidx.glance.unit.c) {
            return 2;
        }
        throw new NoWhenBranchMatchedException();
    }
}
