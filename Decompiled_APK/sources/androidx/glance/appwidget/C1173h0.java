package androidx.glance.appwidget;

import android.widget.RemoteViews;
import android.widget.RemoteViewsService;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;

/* renamed from: androidx.glance.appwidget.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1173h0 implements RemoteViewsService.RemoteViewsFactory {
    public final GlanceRemoteViewsService a;
    public final int b;
    public final int c;
    public final String d;

    public C1173h0(GlanceRemoteViewsService glanceRemoteViewsService, int i, int i2, String str) {
        this.a = glanceRemoteViewsService;
        this.b = i;
        this.c = i2;
        this.d = str;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0086, code lost:
    
        if (r9 == r1) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x009f, code lost:
    
        if (r9.p(r0) == r1) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00a1, code lost:
    
        return r1;
     */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.glance.appwidget.C1173h0 r7, androidx.glance.appwidget.C1162c r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            boolean r0 = r9 instanceof androidx.glance.appwidget.C1169f0
            if (r0 == 0) goto L13
            r0 = r9
            androidx.glance.appwidget.f0 r0 = (androidx.glance.appwidget.C1169f0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.glance.appwidget.f0 r0 = new androidx.glance.appwidget.f0
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L43
            if (r2 == r4) goto L3d
            r7 = 2
            if (r2 == r7) goto L37
            if (r2 != r3) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto La2
        L2f:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlinx.coroutines.j0 r9 = (kotlinx.coroutines.InterfaceC5025j0) r9
            goto L95
        L3d:
            androidx.glance.appwidget.h0 r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L89
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            androidx.glance.appwidget.GlanceRemoteViewsService r9 = r7.a
            android.appwidget.AppWidgetManager r9 = android.appwidget.AppWidgetManager.getInstance(r9)
            int r2 = r7.b
            android.appwidget.AppWidgetProviderInfo r9 = r9.getAppWidgetInfo(r2)
            if (r9 == 0) goto L74
            android.content.ComponentName r9 = r9.provider
            if (r9 == 0) goto L74
            java.lang.String r9 = r9.getClassName()
            if (r9 == 0) goto L74
            java.lang.Class r9 = java.lang.Class.forName(r9)
            java.lang.reflect.Constructor r9 = r9.getDeclaredConstructor(r5)
            java.lang.Object r9 = r9.newInstance(r5)
            java.lang.String r2 = "null cannot be cast to non-null type androidx.glance.appwidget.GlanceAppWidgetReceiver"
            kotlin.jvm.internal.Intrinsics.e(r9, r2)
            com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver r9 = (com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver) r9
            com.quizlet.quizletandroid.ui.widgets.y r9 = com.quizlet.quizletandroid.ui.widgets.y.c
            goto L75
        L74:
            r9 = r5
        L75:
            if (r9 == 0) goto L8d
            androidx.glance.session.p r2 = androidx.glance.session.q.a
            androidx.glance.appwidget.g0 r6 = new androidx.glance.appwidget.g0
            r6.<init>(r7, r8, r9, r5)
            r0.j = r7
            r0.m = r4
            java.lang.Object r9 = r2.a(r6, r0)
            if (r9 != r1) goto L89
            goto La1
        L89:
            kotlinx.coroutines.j0 r9 = (kotlinx.coroutines.InterfaceC5025j0) r9
            if (r9 != 0) goto L95
        L8d:
            androidx.glance.appwidget.y r8 = androidx.glance.appwidget.UnmanagedSessionReceiver.a
            int r7 = r7.b
            androidx.glance.appwidget.C1221y.a(r7)
            r9 = r5
        L95:
            if (r9 == 0) goto La5
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = r9.p(r0)
            if (r7 != r1) goto La2
        La1:
            return r1
        La2:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        La5:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1173h0.a(androidx.glance.appwidget.h0, androidx.glance.appwidget.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final z0 b() {
        z0 z0Var;
        androidx.camera.core.impl.y0 y0Var = GlanceRemoteViewsService.a;
        int i = this.b;
        int i2 = this.c;
        String str = this.d;
        androidx.camera.core.impl.y0 y0Var2 = GlanceRemoteViewsService.a;
        synchronized (y0Var2) {
            z0Var = (z0) y0Var2.a.get(androidx.camera.core.impl.y0.e(i, i2, str));
            if (z0Var == null) {
                z0Var = z0.e;
            }
        }
        return z0Var;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final int getCount() {
        return b().a.length;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final long getItemId(int i) {
        try {
            return b().a[i];
        } catch (ArrayIndexOutOfBoundsException unused) {
            return -1L;
        }
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final /* bridge */ /* synthetic */ RemoteViews getLoadingView() {
        return null;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final RemoteViews getViewAt(int i) {
        try {
            return b().b[i];
        } catch (ArrayIndexOutOfBoundsException unused) {
            return new RemoteViews(this.a.getPackageName(), R.layout.glance_invalid_list_item);
        }
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final int getViewTypeCount() {
        return b().d;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final boolean hasStableIds() {
        return b().c;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onCreate() {
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onDataSetChanged() throws Throwable {
        kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1167e0(this, null));
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onDestroy() {
        androidx.camera.core.impl.y0 y0Var = GlanceRemoteViewsService.a;
        int i = this.b;
        int i2 = this.c;
        String str = this.d;
        androidx.camera.core.impl.y0 y0Var2 = GlanceRemoteViewsService.a;
        synchronized (y0Var2) {
            y0Var2.a.remove(androidx.camera.core.impl.y0.e(i, i2, str));
            Unit unit = Unit.a;
        }
    }
}
