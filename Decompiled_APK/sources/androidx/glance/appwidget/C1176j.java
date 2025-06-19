package androidx.glance.appwidget;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProviderInfo;
import android.content.Context;
import android.os.Bundle;
import android.util.DisplayMetrics;
import androidx.compose.runtime.C0807l0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.snapshots.C0824d;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.appwidget.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1176j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1182m l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ InterfaceC0773a0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1176j(C1182m c1182m, Context context, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1182m;
        this.m = context;
        this.n = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1176j c1176j = new C1176j(this.l, this.m, this.n, hVar);
        c1176j.k = obj;
        return c1176j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1176j) create((C0807l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        C0807l0 c0807l0;
        androidx.glance.state.h hVar;
        C0824d c0824dC;
        long jC;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Context context = this.m;
        C1182m c1182m = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0807l0 c0807l02 = (C0807l0) this.k;
            if (((androidx.compose.runtime.L0) c1182m.i).getValue() != null || (hVar = c1182m.d.b) == null) {
                c0807l0 = c0807l02;
                obj = null;
            } else {
                this.k = c0807l02;
                this.j = 1;
                Object objC = ((androidx.glance.state.f) c1182m.f).c(context, hVar, c1182m.a, this);
                if (objC == aVar) {
                    return aVar;
                }
                c0807l0 = c0807l02;
                obj = objC;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            c0807l0 = (C0807l0) this.k;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        InterfaceC0773a0 interfaceC0773a0 = this.n;
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        C0824d c0824d = hVarK instanceof C0824d ? (C0824d) hVarK : null;
        if (c0824d == null || (c0824dC = c0824d.C(null, null)) == null) {
            throw new IllegalStateException("Cannot create a mutable snapshot of an read-only snapshot");
        }
        try {
            androidx.compose.runtime.snapshots.h hVarJ = c0824dC.j();
            try {
                C1162c c1162c = c1182m.e;
                int i2 = c1162c.a;
                boolean z = false;
                if (Integer.MIN_VALUE <= i2 && i2 < -1) {
                    z = true;
                }
                if (!z) {
                    Object systemService = context.getSystemService("appwidget");
                    Intrinsics.e(systemService, "null cannot be cast to non-null type android.appwidget.AppWidgetManager");
                    AppWidgetManager appWidgetManager = (AppWidgetManager) systemService;
                    DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
                    AppWidgetProviderInfo appWidgetInfo = appWidgetManager.getAppWidgetInfo(c1162c.a);
                    if (appWidgetInfo == null) {
                        jC = 0;
                    } else {
                        int i3 = appWidgetInfo.minWidth;
                        int i4 = 1 & appWidgetInfo.resizeMode;
                        int i5 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                        int iMin = Math.min(i3, i4 != 0 ? appWidgetInfo.minResizeWidth : Integer.MAX_VALUE);
                        int i6 = appWidgetInfo.minHeight;
                        if ((appWidgetInfo.resizeMode & 2) != 0) {
                            i5 = appWidgetInfo.minResizeHeight;
                        }
                        int iMin2 = Math.min(i6, i5);
                        float f = displayMetrics.density;
                        jC = N5.c(iMin / f, iMin2 / f);
                    }
                    interfaceC0773a0.setValue(new androidx.compose.ui.unit.g(jC));
                    InterfaceC0773a0 interfaceC0773a02 = c1182m.j;
                    if (((Bundle) ((androidx.compose.runtime.L0) interfaceC0773a02).getValue()) == null) {
                        ((androidx.compose.runtime.L0) interfaceC0773a02).setValue(appWidgetManager.getAppWidgetOptions(c1162c.a));
                    }
                }
                if (obj != null) {
                    ((androidx.compose.runtime.L0) c1182m.i).setValue(obj);
                }
                c0807l0.setValue(Boolean.TRUE);
                Unit unit = Unit.a;
                androidx.compose.runtime.snapshots.h.q(hVarJ);
                c0824dC.w().c();
                c0824dC.c();
                return Unit.a;
            } catch (Throwable th) {
                androidx.compose.runtime.snapshots.h.q(hVarJ);
                throw th;
            }
        } catch (Throwable th2) {
            c0824dC.c();
            throw th2;
        }
    }
}
