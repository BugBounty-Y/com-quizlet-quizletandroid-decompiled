package com.quizlet.quizletandroid;

import android.content.Context;
import android.os.Handler;
import androidx.work.C1425f;
import androidx.work.EnumC1441o;
import com.quizlet.background.eventlogging.EventLogSyncingWorker;
import com.quizlet.eventlogger.EventLogCounter;
import com.quizlet.eventlogger.IServerErrorListener;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import java.util.LinkedHashSet;
import java.util.Timer;
import java.util.concurrent.TimeUnit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C implements IServerErrorListener {
    public Timer a;
    public com.facebook.appevents.codeless.j b;
    public Handler c;
    public Context d;
    public com.quizlet.quizletandroid.managers.h e;
    public EventLogCounter f;
    public long g;
    public boolean h;
    public com.quizlet.data.connectivity.b i;
    public CurrentUserEvent j;

    @Override // com.quizlet.eventlogger.IServerErrorListener
    public final void a(boolean z) {
        boolean z2 = z || !this.h;
        this.h = !z;
        if (this.a == null || !z2) {
            return;
        }
        timber.log.c.a.a("Resetting sync timer based on network results", new Object[0]);
        c(this.i, z);
    }

    public final void b() {
        if (this.f.a() == 0) {
            return;
        }
        timber.log.c.a.m("Scheduling log job", new Object[0]);
        Context context = this.d;
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.work.impl.r rVarH = androidx.work.impl.r.h(context);
        Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
        EnumC1441o enumC1441o = EnumC1441o.b;
        Intrinsics.checkNotNullParameter(EventLogSyncingWorker.class, "workerClass");
        androidx.work.C c = new androidx.work.C(EventLogSyncingWorker.class);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        androidx.work.A networkType = androidx.work.A.b;
        Intrinsics.checkNotNullParameter(networkType, "networkType");
        rVarH.a("event_log_sync", enumC1441o, (androidx.work.D) ((androidx.work.C) c.j(new C1425f(new androidx.work.impl.utils.g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet)))).a()).c();
    }

    public final void c(com.quizlet.data.connectivity.b bVar, boolean z) {
        com.facebook.appevents.codeless.j jVar = this.b;
        if (jVar != null) {
            jVar.cancel();
        }
        if (this.a == null) {
            this.a = new Timer("LogSchedulerTimer");
        }
        this.b = new com.facebook.appevents.codeless.j(this, 2);
        if (z) {
            timber.log.c.a.a("Backing off sync timer due to previous failure", new Object[0]);
            this.g = Math.min(TimeUnit.DAYS.toMillis(1L), this.g * 2);
        } else {
            timber.log.c.a.a("Syncing at normal frequency", new Object[0]);
            this.g = bVar.b ? 60000L : 300000L;
        }
        Timer timer = this.a;
        com.facebook.appevents.codeless.j jVar2 = this.b;
        long j = this.g;
        timer.schedule(jVar2, j, j);
    }
}
