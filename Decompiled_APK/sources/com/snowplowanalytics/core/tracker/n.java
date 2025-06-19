package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Handler;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.core.app.RunnableC1014a;
import com.google.android.datatransport.cct.internal.s;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.Regex;

/* loaded from: classes3.dex */
public final class n {
    public boolean A;
    public boolean B;
    public boolean C;
    public com.quizlet.data.repository.classmembership.c D;
    public final m E;
    public final m F;
    public final m G;
    public final m H;
    public final m I;
    public final String a;
    public final boolean b;
    public final Activity c;
    public final s d;
    public final String e;
    public final AtomicBoolean f;
    public final i g;
    public final com.snowplowanalytics.core.emitter.a h;
    public l i;
    public com.snowplowanalytics.core.session.c j;
    public boolean k;
    public com.snowplowanalytics.snowplow.tracker.a l;
    public com.snowplowanalytics.snowplow.tracker.b m;
    public long n;
    public long o;
    public boolean p;
    public final TimeUnit q;
    public boolean r;
    public boolean s;
    public boolean t;
    public boolean u;
    public boolean v;
    public boolean w;
    public String x;
    public final Runnable[] y;
    public boolean z;

    public n(com.snowplowanalytics.core.emitter.a emitter, String appId, List list, com.snowplowanalytics.snowplow.tracker.d dVar, Activity context, androidx.compose.ui.viewinterop.b bVar) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        m mVar;
        m mVar2;
        m mVar3;
        m mVar4;
        m mVar5;
        int i;
        Intrinsics.checkNotNullParameter(emitter, "emitter");
        Intrinsics.checkNotNullParameter("appTracker", "namespace");
        Intrinsics.checkNotNullParameter(appId, "appId");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = appId;
        this.d = new s(11);
        this.e = "andr-6.2.0";
        int i2 = 1;
        this.f = new AtomicBoolean(true);
        this.g = new i(list, dVar == null ? new com.snowplowanalytics.snowplow.tracker.d() : dVar, context);
        this.h = emitter;
        TimeUnit timeUnit = p.a;
        this.k = true;
        this.l = com.snowplowanalytics.snowplow.tracker.a.Mobile;
        com.snowplowanalytics.snowplow.tracker.b bVar2 = com.snowplowanalytics.snowplow.tracker.b.OFF;
        this.m = bVar2;
        this.n = 1800L;
        this.o = 1800L;
        this.p = false;
        TimeUnit timeUnit2 = p.a;
        this.q = timeUnit2;
        this.r = p.g;
        this.s = false;
        this.t = p.h;
        this.u = p.k;
        this.v = p.i;
        this.w = false;
        Runnable[] runnableArr = {null, null, null, null};
        this.y = runnableArr;
        this.z = p.b;
        this.A = false;
        this.B = p.c;
        this.C = p.f;
        m mVar6 = new m(this, 3);
        this.E = mVar6;
        m mVar7 = new m(this, 4);
        this.F = mVar7;
        m mVar8 = new m(this, 2);
        this.G = mVar8;
        m mVar9 = new m(this, 1);
        this.H = mVar9;
        m mVar10 = new m(this, 0);
        this.I = mVar10;
        this.c = context;
        bVar.invoke(this);
        com.snowplowanalytics.core.emitter.c.a(false, emitter.a, new com.google.firebase.crashlytics.internal.metadata.q(emitter, 23));
        String str = this.x;
        if (str != null) {
            String strReplace = new Regex("[^A-Za-z0-9.-]").replace(str, "");
            if (strReplace.length() > 0) {
                String str2 = this.e + ' ' + strReplace;
                if (!this.b) {
                    this.e = str2;
                }
            }
        }
        if (this.s && this.m == bVar2) {
            com.snowplowanalytics.snowplow.tracker.b level = com.snowplowanalytics.snowplow.tracker.b.ERROR;
            Intrinsics.checkNotNullParameter(level, "level");
            if (!this.b) {
                this.m = level;
            }
        }
        com.snowplowanalytics.snowplow.tracker.b newLevel = this.m;
        Intrinsics.checkNotNullParameter(newLevel, "newLevel");
        e.a = newLevel.a;
        if (this.z) {
            mVar = mVar6;
            mVar2 = mVar7;
            mVar3 = mVar8;
            mVar4 = mVar9;
            mVar5 = mVar10;
            this.j = com.snowplowanalytics.core.session.c.q.a(context, this.n, this.o, timeUnit2, runnableArr, this.p);
        } else {
            mVar = mVar6;
            mVar2 = mVar7;
            mVar3 = mVar8;
            mVar4 = mVar9;
            mVar5 = mVar10;
        }
        com.snowplowanalytics.core.utils.c.a("SnowplowTrackerDiagnostic", mVar4);
        com.snowplowanalytics.core.utils.c.a("SnowplowScreenView", mVar2);
        com.snowplowanalytics.core.utils.c.a("SnowplowLifecycleTracking", mVar);
        com.snowplowanalytics.core.utils.c.a("SnowplowInstallTracking", mVar3);
        com.snowplowanalytics.core.utils.c.a("SnowplowCrashReporting", mVar5);
        if (this.r && !(Thread.getDefaultUncaughtExceptionHandler() instanceof c)) {
            Thread.setDefaultUncaughtExceptionHandler(new c());
        }
        if (this.u) {
            Intrinsics.checkNotNullParameter(context, "context");
            com.snowplowanalytics.core.emitter.c.a(false, "b", new RunnableC1014a(i2, context));
        }
        if (this.v) {
            synchronized (a.b) {
                try {
                    Intrinsics.checkNotNullParameter(context, "context");
                    if (a.c == null) {
                        a aVar = new a();
                        Context applicationContext = context.getApplicationContext();
                        Application application = applicationContext instanceof Application ? (Application) applicationContext : null;
                        if (application != null) {
                            application.registerActivityLifecycleCallbacks(aVar);
                        }
                        a.c = aVar;
                    }
                    Intrinsics.d(a.c);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        if (this.t) {
            synchronized (com.snowplowanalytics.core.session.b.a) {
                Intrinsics.checkNotNullParameter(context, "context");
                if (com.snowplowanalytics.core.session.b.b == 1) {
                    com.snowplowanalytics.core.session.b.b = 2;
                    new Handler(context.getMainLooper()).post(new RunnableC0131h(25));
                }
            }
            a(new com.snowplowanalytics.core.screenviews.b(3));
        }
        com.snowplowanalytics.core.session.c cVar = this.j;
        if (cVar != null) {
            i = 0;
            cVar.d(false);
            Intrinsics.checkNotNullExpressionValue("n", "TAG");
            e.a("n", "Session checking has been resumed.", new Object[0]);
        } else {
            i = 0;
        }
        this.b = true;
        Intrinsics.checkNotNullExpressionValue("n", "TAG");
        e.e("n", "Tracker created successfully.", new Object[i]);
    }

    public final void a(com.snowplowanalytics.core.statemachine.f stateMachine) {
        Intrinsics.checkNotNullParameter(stateMachine, "stateMachine");
        s sVar = this.d;
        synchronized (sVar) {
            try {
                Intrinsics.checkNotNullParameter(stateMachine, "stateMachine");
                com.snowplowanalytics.core.statemachine.f fVar = (com.snowplowanalytics.core.statemachine.f) ((HashMap) sVar.b).get(stateMachine.getIdentifier());
                if (fVar != null) {
                    if (stateMachine.getClass().equals(fVar.getClass())) {
                        return;
                    } else {
                        sVar.q(stateMachine.getIdentifier());
                    }
                }
                ((HashMap) sVar.b).put(stateMachine.getIdentifier(), stateMachine);
                ((HashMap) sVar.c).put(stateMachine, stateMachine.getIdentifier());
                s.b((HashMap) sVar.d, stateMachine.k(), stateMachine);
                s.b((HashMap) sVar.e, stateMachine.d(), stateMachine);
                s.b((HashMap) sVar.f, stateMachine.f(), stateMachine);
                s.b((HashMap) sVar.g, stateMachine.j(), stateMachine);
                s.b((HashMap) sVar.a, stateMachine.c(), stateMachine);
                s.b((HashMap) sVar.h, stateMachine.a(), stateMachine);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        com.snowplowanalytics.core.session.c cVar = this.j;
        if (cVar != null) {
            cVar.d(true);
            Intrinsics.checkNotNullExpressionValue("n", "TAG");
            e.a("n", "Session checking has been paused.", new Object[0]);
        }
    }

    public final UUID c(com.snowplowanalytics.snowplow.event.a event) {
        LinkedList linkedList;
        List listG;
        Intrinsics.checkNotNullParameter(event, "event");
        if (!this.f.get()) {
            return null;
        }
        s sVar = this.d;
        synchronized (sVar) {
            try {
                Intrinsics.checkNotNullParameter(event, "event");
                linkedList = new LinkedList();
                if (event instanceof com.snowplowanalytics.snowplow.event.a) {
                    LinkedList<com.snowplowanalytics.core.statemachine.f> linkedList2 = new LinkedList();
                    List list = (List) ((HashMap) sVar.h).get(event.b());
                    if (list != null) {
                        linkedList2.addAll(list);
                    }
                    List list2 = (List) ((HashMap) sVar.h).get("*");
                    if (list2 != null) {
                        linkedList2.addAll(list2);
                    }
                    for (com.snowplowanalytics.core.statemachine.f fVar : linkedList2) {
                        if (((String) ((HashMap) sVar.c).get(fVar)) != null && (listG = fVar.g(event)) != null) {
                            linkedList.addAll(listG);
                        }
                    }
                }
            } finally {
            }
        }
        ArrayList arrayListC0 = CollectionsKt.c0(linkedList, A.b(event));
        Iterator it2 = arrayListC0.iterator();
        while (it2.hasNext()) {
            ((com.snowplowanalytics.snowplow.event.a) it2.next()).getClass();
            Intrinsics.checkNotNullParameter(this, "tracker");
        }
        J j = new J();
        synchronized (this) {
            try {
                ArrayList arrayList = new ArrayList(C.q(arrayListC0, 10));
                Iterator it3 = arrayListC0.iterator();
                while (it3.hasNext()) {
                    com.snowplowanalytics.snowplow.event.a aVar = (com.snowplowanalytics.snowplow.event.a) it3.next();
                    q qVar = new q(aVar, this.d.s(aVar));
                    d(qVar);
                    arrayList.add(new Pair(aVar, qVar));
                }
                j.a = arrayList;
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        com.snowplowanalytics.core.emitter.c.a(!(event instanceof com.snowplowanalytics.snowplow.event.g), "n", new com.skydoves.balloon.compose.a(5, j, this));
        return ((q) ((Pair) CollectionsKt.U((List) j.a)).b).e;
    }

    public final void d(q qVar) {
        com.snowplowanalytics.snowplow.entity.a aVar;
        androidx.core.util.a aVar2;
        if (qVar.g || !this.z) {
            return;
        }
        String eventId = qVar.e.toString();
        Intrinsics.checkNotNullExpressionValue(eventId, "event.eventId.toString()");
        long j = qVar.f;
        com.snowplowanalytics.core.session.c cVar = this.j;
        if (cVar == null) {
            Intrinsics.checkNotNullExpressionValue("n", "TAG");
            e.d("n", "Session not ready or method getHasLoadedFromFile returned false with eventId: %s", eventId);
            return;
        }
        boolean z = this.w;
        synchronized (cVar) {
            try {
                Intrinsics.checkNotNullParameter(eventId, "eventId");
                Intrinsics.checkNotNullExpressionValue("c", "TAG");
                e.e("c", "Getting session context...", new Object[0]);
                aVar = null;
                if (cVar.h) {
                    if (!cVar.g.get()) {
                        com.google.firebase.crashlytics.internal.settings.d dVar = cVar.e;
                        Long l = dVar != null ? (Long) dVar.i : null;
                        if (l != null) {
                            long jCurrentTimeMillis = System.currentTimeMillis();
                            long j2 = cVar.f.get() ? cVar.j : cVar.i;
                            if (jCurrentTimeMillis < l.longValue() || jCurrentTimeMillis - l.longValue() > j2) {
                            }
                        }
                    }
                    Intrinsics.checkNotNullExpressionValue("c", "TAG");
                    e.a("c", "Update session information.", new Object[0]);
                    cVar.e(j, eventId);
                    com.google.firebase.crashlytics.internal.settings.d dVar2 = cVar.e;
                    if (dVar2 != null && (aVar2 = cVar.o) != null) {
                        Thread thread = new Thread(new com.skydoves.balloon.compose.a(3, aVar2, dVar2));
                        thread.setDaemon(true);
                        thread.start();
                    }
                    if (cVar.f.get()) {
                        com.snowplowanalytics.core.session.c.a(cVar.n);
                    } else {
                        com.snowplowanalytics.core.session.c.a(cVar.m);
                    }
                    if (!cVar.a) {
                        cVar.c();
                    }
                }
                com.google.firebase.crashlytics.internal.settings.d dVar3 = cVar.e;
                if (dVar3 == null) {
                    Intrinsics.checkNotNullExpressionValue("c", "TAG");
                    e.e("c", "Session state not present", new Object[0]);
                } else {
                    boolean z2 = cVar.h;
                    Integer num = (Integer) dVar3.h;
                    dVar3.h = Integer.valueOf((num != null ? num.intValue() : 0) + 1);
                    if (z2) {
                        dVar3.i = Long.valueOf(System.currentTimeMillis());
                    }
                    if (cVar.a) {
                        cVar.c();
                    }
                    HashMap values = new HashMap(dVar3.a());
                    if (z) {
                        values.put("userId", "00000000-0000-0000-0000-000000000000");
                        values.put("previousSessionId", null);
                    }
                    Intrinsics.checkNotNullParameter(values, "values");
                    aVar = new com.snowplowanalytics.snowplow.entity.a("iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2", values);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (aVar != null) {
            ((ArrayList) qVar.b()).add(aVar);
        }
    }
}
