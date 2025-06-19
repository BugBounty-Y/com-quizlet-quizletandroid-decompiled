package com.quizlet.quizletandroid.ui.widgets;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.glance.appwidget.C1163c0;
import androidx.glance.appwidget.C1165d0;
import androidx.glance.appwidget.Y;
import androidx.glance.appwidget.Z;
import androidx.work.C1425f;
import androidx.work.EnumC1441o;
import androidx.work.K;
import androidx.work.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3251r7;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import com.quizlet.background.widget.WidgetUpdateWorker;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.O;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletWidgetReceiver extends AppWidgetProvider {
    public com.quizlet.data.repository.school.membership.a b;
    public final kotlinx.coroutines.scheduling.e a = O.a;
    public volatile boolean c = false;
    public final Object d = new Object();

    public static final void a(QuizletWidgetReceiver quizletWidgetReceiver, kotlinx.coroutines.C c, Context context) {
        kotlinx.coroutines.E.A(c, null, null, new C1165d0(context, quizletWidgetReceiver, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x008b A[Catch: all -> 0x0047, CancellationException -> 0x00b9, TryCatch #4 {CancellationException -> 0x00b9, all -> 0x0047, blocks: (B:21:0x0040, B:28:0x0051, B:29:0x0059, B:30:0x005a, B:31:0x0062, B:32:0x0063, B:48:0x00ae, B:38:0x0079, B:40:0x008b, B:42:0x0096, B:44:0x00a2, B:43:0x009e, B:46:0x00a6, B:47:0x00ad, B:35:0x006e), top: B:53:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00a6 A[Catch: all -> 0x0047, CancellationException -> 0x00b9, TryCatch #4 {CancellationException -> 0x00b9, all -> 0x0047, blocks: (B:21:0x0040, B:28:0x0051, B:29:0x0059, B:30:0x005a, B:31:0x0062, B:32:0x0063, B:48:0x00ae, B:38:0x0079, B:40:0x008b, B:42:0x0096, B:44:0x00a2, B:43:0x009e, B:46:0x00a6, B:47:0x00ad, B:35:0x006e), top: B:53:0x0006 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.content.Context r8, android.content.Intent r9) {
        /*
            r7 = this;
            java.lang.String r0 = "appWidgetIds"
            java.lang.String r1 = r9.getAction()     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            if (r1 == 0) goto L1b
            int r2 = r1.hashCode()     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            r3 = -19011148(0xfffffffffedde9b4, float:-1.4748642E38)
            if (r2 == r3) goto L6e
            r3 = 649033583(0x26af776f, float:1.2175437E-15)
            if (r2 == r3) goto L63
            r0 = 1989767543(0x76997177, float:1.5560991E33)
            if (r2 == r0) goto L1f
        L1b:
            r2 = r7
            r3 = r8
            goto Lae
        L1f:
            java.lang.String r0 = "ACTION_TRIGGER_LAMBDA"
            boolean r0 = r1.equals(r0)     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            if (r0 != 0) goto L28
            goto L1b
        L28:
            java.lang.String r0 = "EXTRA_ACTION_KEY"
            java.lang.String r5 = r9.getStringExtra(r0)     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            if (r5 == 0) goto L5a
            java.lang.String r0 = "EXTRA_APPWIDGET_ID"
            r1 = -1
            int r4 = r9.getIntExtra(r0, r1)     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            if (r4 == r1) goto L51
            kotlinx.coroutines.scheduling.e r9 = r7.a     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            androidx.glance.appwidget.a0 r1 = new androidx.glance.appwidget.a0     // Catch: java.lang.Throwable -> L4b java.util.concurrent.CancellationException -> L4e
            r6 = 0
            r2 = r7
            r3 = r8
            r1.<init>(r2, r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3251r7.b(r7, r9, r1)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            return
        L47:
            r0 = move-exception
        L48:
            r8 = r0
            goto Lb2
        L4b:
            r0 = move-exception
            r2 = r7
            goto L48
        L4e:
            r2 = r7
            goto Lb9
        L51:
            r2 = r7
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            java.lang.String r9 = "Intent is missing AppWidgetId extra"
            r8.<init>(r9)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            throw r8     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
        L5a:
            r2 = r7
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            java.lang.String r9 = "Intent is missing ActionKey extra"
            r8.<init>(r9)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            throw r8     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
        L63:
            r2 = r7
            r3 = r8
            java.lang.String r8 = "androidx.glance.appwidget.action.DEBUG_UPDATE"
            boolean r8 = r1.equals(r8)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            if (r8 != 0) goto L79
            goto Lae
        L6e:
            r2 = r7
            r3 = r8
            java.lang.String r8 = "android.intent.action.LOCALE_CHANGED"
            boolean r8 = r1.equals(r8)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            if (r8 != 0) goto L79
            goto Lae
        L79:
            android.appwidget.AppWidgetManager r8 = android.appwidget.AppWidgetManager.getInstance(r3)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            java.lang.String r1 = r3.getPackageName()     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            java.lang.Class r4 = r7.getClass()     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            java.lang.String r4 = r4.getCanonicalName()     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            if (r4 == 0) goto La6
            android.content.ComponentName r5 = new android.content.ComponentName     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            r5.<init>(r1, r4)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            boolean r1 = r9.hasExtra(r0)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            if (r1 == 0) goto L9e
            int[] r9 = r9.getIntArrayExtra(r0)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            kotlin.jvm.internal.Intrinsics.d(r9)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            goto La2
        L9e:
            int[] r9 = r8.getAppWidgetIds(r5)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
        La2:
            r7.onUpdate(r3, r8, r9)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            return
        La6:
            java.lang.String r8 = "no canonical name"
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            r9.<init>(r8)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            throw r9     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
        Lae:
            super.onReceive(r3, r9)     // Catch: java.lang.Throwable -> L47 java.util.concurrent.CancellationException -> Lb9
            return
        Lb2:
            java.lang.String r9 = "GlanceAppWidget"
            java.lang.String r0 = "Error in Glance App Widget"
            android.util.Log.e(r9, r0, r8)
        Lb9:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver.b(android.content.Context, android.content.Intent):void");
    }

    @Override // android.appwidget.AppWidgetProvider
    public final void onAppWidgetOptionsChanged(Context context, AppWidgetManager appWidgetManager, int i, Bundle bundle) {
        AbstractC3251r7.b(this, this.a, new Y(this, context, i, bundle, null));
    }

    @Override // android.appwidget.AppWidgetProvider
    public final void onDeleted(Context context, int[] iArr) {
        AbstractC3251r7.b(this, this.a, new Z(this, context, iArr, null));
    }

    @Override // android.appwidget.AppWidgetProvider
    public final void onDisabled(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onDisabled(context);
        com.quizlet.data.repository.school.membership.a aVar = this.b;
        if (aVar == null) {
            Intrinsics.m("widgetUpdateSyncUtil");
            throw null;
        }
        androidx.work.impl.r workManagerImpl = (androidx.work.impl.r) aVar.b;
        Intrinsics.checkNotNullParameter("WidgetUpdate", "name");
        Intrinsics.checkNotNullParameter(workManagerImpl, "workManagerImpl");
        androidx.work.B b = workManagerImpl.b.m;
        ExecutorC0060p executorC0060p = workManagerImpl.d.a;
        Intrinsics.checkNotNullExpressionValue(executorC0060p, "workManagerImpl.workTask…ecutor.serialTaskExecutor");
        AbstractC3402v2.c(b, "CancelWorkByName_WidgetUpdate", executorC0060p, new androidx.work.impl.utils.a(workManagerImpl, 0));
    }

    @Override // android.appwidget.AppWidgetProvider
    public final void onEnabled(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onEnabled(context);
        com.quizlet.data.repository.school.membership.a aVar = this.b;
        if (aVar == null) {
            Intrinsics.m("widgetUpdateSyncUtil");
            throw null;
        }
        TimeUnit repeatIntervalTimeUnit = TimeUnit.MINUTES;
        Intrinsics.checkNotNullParameter(WidgetUpdateWorker.class, "workerClass");
        Intrinsics.checkNotNullParameter(repeatIntervalTimeUnit, "repeatIntervalTimeUnit");
        K k = new K(WidgetUpdateWorker.class);
        androidx.work.impl.model.q qVar = (androidx.work.impl.model.q) k.c;
        long millis = repeatIntervalTimeUnit.toMillis(120L);
        qVar.getClass();
        String str = androidx.work.impl.model.q.y;
        if (millis < 900000) {
            androidx.work.z.c().f(str, "Interval duration lesser than minimum allowed value; Changed to 900000");
        }
        long j = millis < 900000 ? 900000L : millis;
        long j2 = millis < 900000 ? 900000L : millis;
        if (j < 900000) {
            androidx.work.z.c().f(str, "Interval duration lesser than minimum allowed value; Changed to 900000");
        }
        qVar.h = j >= 900000 ? j : 900000L;
        if (j2 < 300000) {
            androidx.work.z.c().f(str, "Flex duration lesser than minimum allowed value; Changed to 300000");
        }
        if (j2 > qVar.h) {
            androidx.work.z.c().f(str, "Flex duration greater than interval duration; Changed to " + j);
        }
        qVar.i = kotlin.ranges.l.d(j2, 300000L, qVar.h);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        androidx.work.A networkType = androidx.work.A.b;
        Intrinsics.checkNotNullParameter(networkType, "networkType");
        K k2 = (K) k.j(new C1425f(new androidx.work.impl.utils.g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet)));
        Intrinsics.checkNotNullParameter("WidgetUpdate", "tag");
        ((Set) k2.d).add("WidgetUpdate");
        new androidx.work.impl.n((androidx.work.impl.r) aVar.b, "WidgetUpdate", EnumC1441o.a, Collections.singletonList((L) k2.a())).c();
    }

    @Override // android.appwidget.AppWidgetProvider, android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        if (!this.c) {
            synchronized (this.d) {
                try {
                    if (!this.c) {
                        this.b = new com.quizlet.data.repository.school.membership.a(((com.quizlet.quizletandroid.u) ((z) Q6.b(context))).x1());
                        this.c = true;
                    }
                } finally {
                }
            }
        }
        b(context, intent);
    }

    @Override // android.appwidget.AppWidgetProvider
    public final void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] iArr) {
        AbstractC3251r7.b(this, this.a, new C1163c0(this, context, iArr, null));
    }
}
