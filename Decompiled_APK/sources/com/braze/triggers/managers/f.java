package com.braze.triggers.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1477c;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IEventSubscriber;
import com.braze.events.NoMatchingTriggerEvent;
import com.braze.events.internal.c0;
import com.braze.managers.C1500m;
import com.braze.managers.U;
import com.braze.requests.framework.o;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.JsonUtils;
import com.braze.support.w;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.StringsKt;
import kotlin.text.x;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f {
    public static final long p = TimeUnit.SECONDS.toMillis(30);
    public static final String q = BrazeLogger.getBrazeLogTag((Class<?>) f.class);
    public final Context a;
    public final C1500m b;
    public final com.braze.events.e c;
    public final com.braze.events.e d;
    public final long e;
    public final SharedPreferences f;
    public final b g;
    public final g h;
    public final Queue i;
    public final LinkedHashMap j;
    public long k;
    public volatile long l;
    public final ReentrantLock m;
    public final ReentrantLock n;
    public final com.braze.requests.framework.g o;

    public f(Context context, C1500m brazeManager, com.braze.events.e internalEventPublisher, com.braze.events.e externalEventPublisher, BrazeConfigurationProvider configurationProvider, String str, String apiKey, com.braze.requests.framework.g requestFramework) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(requestFramework, "requestFramework");
        this.m = new ReentrantLock();
        this.n = new ReentrantLock();
        this.a = context.getApplicationContext();
        this.b = brazeManager;
        this.c = internalEventPublisher;
        Intrinsics.checkNotNullParameter(externalEventPublisher, "<set-?>");
        this.d = externalEventPublisher;
        this.e = configurationProvider.getTriggerActionMinimumTimeIntervalInSeconds();
        this.f = assistantMode.refactored.a.g(0, context, "com.appboy.storage.triggers.actions", str, apiKey);
        this.g = new b(context, apiKey);
        this.h = new g(context, str, apiKey);
        this.j = g();
        this.i = new ArrayDeque();
        this.o = requestFramework;
        k();
    }

    public static final String a(String str) {
        return AbstractC1475a.a("Received null or blank serialized triggered action string for action id ", str, " from shared preferences. Not parsing.");
    }

    public static final String c(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Trigger manager received reenqueue with action with id: <"), ((com.braze.triggers.actions.g) aVar).a, ">.");
    }

    public static final String d(com.braze.triggers.actions.a aVar) {
        return d0.r(new StringBuilder("Registering triggered action id "), ((com.braze.triggers.actions.g) aVar).a, ' ');
    }

    public static final String e() {
        return "Test triggered actions found, triggering test event.";
    }

    public static final String f() {
        return "No test triggered actions found.";
    }

    public static final String g(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Trigger manager received failed triggered action with id: <"), ((com.braze.triggers.actions.g) aVar).a, ">. Will attempt to perform fallback triggered actions, if present.");
    }

    public static final String h() {
        return "Encountered unexpected exception while parsing stored triggered actions.";
    }

    public static final String i() {
        return "Triggered action has no trigger metadata and cannot fallback. Doing nothing.";
    }

    public static final String j() {
        return "Triggered action has no fallback action to perform. Doing nothing.";
    }

    public static final String l() {
        return "Subscribing to trigger dispatch events.";
    }

    public static final String m() {
        return "Executing pending events after trigger dispatch completed.";
    }

    public final void b(long j) {
        this.k = this.l;
        this.l = j;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(10, j), 7, (Object) null);
    }

    public final void k() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new i(7), 12, (Object) null);
        ((com.braze.events.d) this.c).c(c0.class, (IEventSubscriber) new com.braze.dispatch.m(this, 3));
    }

    public static final String a(long j) {
        return d0.n(j, "TriggerManager lastDisplayTimeSeconds updated to ");
    }

    public static final String e(com.braze.triggers.events.b bVar) {
        return "Failed to match triggered action for incoming <" + bVar.a() + ">.";
    }

    public static final String f(com.braze.triggers.actions.a aVar) {
        return "Fallback trigger has expired. Trigger id: " + ((com.braze.triggers.actions.g) aVar).a;
    }

    public static final String e(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Retrieving templated triggered action id "), ((com.braze.triggers.actions.g) aVar).a, " from local storage.");
    }

    public static final String b(List list) {
        return "Registering " + list.size() + " new triggered actions.";
    }

    public static final String c(com.braze.triggers.events.b bVar) {
        return "No action found for " + bVar.a() + " event, publishing NoMatchingTriggerEvent";
    }

    public final LinkedHashMap g() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Map<String, ?> all = this.f.getAll();
        if (all != null && !all.isEmpty()) {
            try {
                for (String str : CollectionsKt.A0(all.keySet())) {
                    String string = this.f.getString(str, null);
                    if (string != null && !StringsKt.O(string)) {
                        com.braze.triggers.actions.h hVarB = com.braze.triggers.utils.c.a.b(new JSONObject(string), this.b);
                        if (hVarB != null) {
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(hVarB, 11), 14, (Object) null);
                            linkedHashMap.put(hVarB.a, hVarB);
                        }
                    } else {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str, 18), 12, (Object) null);
                    }
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new i(6), 8, (Object) null);
            }
        }
        return linkedHashMap;
    }

    public static final String c() {
        return "In flight trigger requests is empty. Executing any pending trigger events.";
    }

    public final void b(com.braze.triggers.actions.a action) {
        Intrinsics.checkNotNullParameter(action, "action");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(action, 4), 14, (Object) null);
        b(this.k);
        this.k = 0L;
        this.h.d(action);
    }

    public static final String d() {
        return "Trigger request is in-flight. Not processing trigger event.";
    }

    public final void a(List triggeredActions) {
        Intrinsics.checkNotNullParameter(triggeredActions, "triggeredActions");
        com.braze.triggers.events.h hVar = new com.braze.triggers.events.h();
        ReentrantLock reentrantLock = this.m;
        reentrantLock.lock();
        try {
            this.j.clear();
            SharedPreferences.Editor editorClear = this.f.edit().clear();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new U(triggeredActions, 2), 14, (Object) null);
            Iterator it2 = triggeredActions.iterator();
            boolean z = false;
            while (it2.hasNext()) {
                com.braze.triggers.actions.a aVar = (com.braze.triggers.actions.a) it2.next();
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(aVar, 5), 14, (Object) null);
                this.j.put(((com.braze.triggers.actions.g) aVar).a, aVar);
                editorClear.putString(((com.braze.triggers.actions.g) aVar).a, String.valueOf(aVar.forJsonPut()));
                if (((com.braze.triggers.actions.g) aVar).b(hVar)) {
                    z = true;
                }
            }
            editorClear.apply();
            Unit unit = Unit.a;
            reentrantLock.unlock();
            this.h.a(triggeredActions);
            this.g.a(triggeredActions);
            if (z) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new i(4), 12, (Object) null);
                a((com.braze.triggers.events.i) hVar);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(5), 14, (Object) null);
            }
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final com.braze.triggers.actions.a d(com.braze.triggers.events.b event) {
        Intrinsics.checkNotNullParameter(event, "event");
        ReentrantLock reentrantLock = this.m;
        reentrantLock.lock();
        try {
            J j = new J();
            ArrayList arrayList = new ArrayList();
            Iterator it2 = this.j.values().iterator();
            int i = Integer.MIN_VALUE;
            while (it2.hasNext()) {
                com.braze.triggers.actions.g gVar = (com.braze.triggers.actions.g) ((com.braze.triggers.actions.a) it2.next());
                if (gVar.b(event) && this.h.a(gVar) && c.a(event, gVar, this.l, this.e)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new m(gVar, 0), 14, (Object) null);
                    int i2 = gVar.b.c;
                    if (i2 > i) {
                        j.a = gVar;
                        i = i2;
                    }
                    arrayList.add(gVar);
                }
            }
            Object obj = j.a;
            if (obj == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.triggers.actions.j(event, 4), 14, (Object) null);
                reentrantLock.unlock();
                return null;
            }
            arrayList.remove(obj);
            ((com.braze.triggers.actions.g) ((com.braze.triggers.actions.a) j.a)).d = new com.braze.triggers.utils.b(arrayList);
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(2, event, j), 14, (Object) null);
            com.braze.triggers.actions.a aVar = (com.braze.triggers.actions.a) j.a;
            reentrantLock.unlock();
            return aVar;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String b(com.braze.triggers.events.b bVar) {
        return "New incoming <" + bVar.a() + ">. Searching for matching triggers.";
    }

    public final void b() {
        ReentrantLock reentrantLock = this.n;
        reentrantLock.lock();
        try {
            if (a()) {
                reentrantLock.unlock();
                return;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(2), 14, (Object) null);
            while (!((ArrayDeque) this.i).isEmpty()) {
                com.braze.triggers.events.b bVar = (com.braze.triggers.events.b) ((ArrayDeque) this.i).poll();
                if (bVar != null) {
                    a(bVar);
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final void a(com.braze.triggers.events.i triggerEvent) {
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        ReentrantLock reentrantLock = this.n;
        reentrantLock.lock();
        try {
            ((ArrayDeque) this.i).add(triggerEvent);
            if (!a()) {
                b();
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(3), 7, (Object) null);
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final void a(com.braze.triggers.events.b triggerEvent, com.braze.triggers.actions.a failedAction) {
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        Intrinsics.checkNotNullParameter(failedAction, "failedAction");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        String str = q;
        BrazeLogger.brazelog$default(brazeLogger, str, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(failedAction, 6), 14, (Object) null);
        com.braze.triggers.utils.b bVar = ((com.braze.triggers.actions.g) failedAction).d;
        if (bVar == null) {
            BrazeLogger.brazelog$default(brazeLogger, str, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(9), 14, (Object) null);
            return;
        }
        com.braze.triggers.actions.a aVar = (com.braze.triggers.actions.a) bVar.a.poll();
        if (aVar == null) {
            BrazeLogger.brazelog$default(brazeLogger, str, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(10), 14, (Object) null);
            return;
        }
        com.braze.triggers.actions.g gVar = (com.braze.triggers.actions.g) aVar;
        gVar.d = bVar;
        Map remoteAssetToLocalAssetPaths = this.g.a(aVar);
        Intrinsics.checkNotNullParameter(remoteAssetToLocalAssetPaths, "remoteAssetToLocalAssetPaths");
        ((com.braze.triggers.actions.h) aVar).f = new HashMap(remoteAssetToLocalAssetPaths);
        long j = ((com.braze.triggers.events.i) triggerEvent).b;
        long j2 = gVar.b.e;
        long millis = TimeUnit.SECONDS.toMillis(r0.d);
        long j3 = j2 != -1 ? j2 + j : j + millis + p;
        if (j3 < DateTimeUtils.nowInMilliseconds()) {
            BrazeLogger.brazelog$default(brazeLogger, str, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(aVar, 7), 14, (Object) null);
            a(triggerEvent, aVar);
        } else {
            long jMax = Math.max(0L, (millis + j) - DateTimeUtils.nowInMilliseconds());
            BrazeLogger.brazelog$default(brazeLogger, str, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new l(aVar, jMax, 0), 14, (Object) null);
            BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, Long.valueOf(jMax), null, new e(aVar, this, triggerEvent, j3, null), 2, null);
        }
    }

    public static final String a(com.braze.triggers.actions.a aVar, long j) {
        return "Performing fallback triggered action with id: <" + ((com.braze.triggers.actions.g) aVar).a + "> with a delay: " + j + " ms";
    }

    public static final void a(f fVar, c0 it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) fVar, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new i(8), 6, (Object) null);
        fVar.b();
    }

    public final void a(com.braze.triggers.events.b event) {
        Intrinsics.checkNotNullParameter(event, "triggerEvent");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.triggers.actions.j(event, 2), 14, (Object) null);
        com.braze.triggers.actions.a action = d(event);
        if (action != null) {
            Intrinsics.checkNotNullParameter(event, "event");
            Intrinsics.checkNotNullParameter(action, "action");
            Map remoteAssetToLocalAssetPaths = this.g.a(action);
            Intrinsics.checkNotNullParameter(remoteAssetToLocalAssetPaths, "remoteAssetToLocalAssetPaths");
            ((com.braze.triggers.actions.h) action).f = new HashMap(remoteAssetToLocalAssetPaths);
            int i = ((com.braze.triggers.actions.g) action).b.e;
            long j = i != -1 ? ((com.braze.triggers.events.i) event).b + i : -1L;
            long millis = TimeUnit.SECONDS.toMillis(r0.d);
            BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, Long.valueOf(millis), null, new d(action, this, event, j, millis, null), 2, null);
            return;
        }
        String strA = event.a();
        int iHashCode = strA.hashCode();
        if (iHashCode != 3417674) {
            if (iHashCode != 717572172) {
                if (iHashCode != 1743324417 || !strA.equals("purchase")) {
                    return;
                }
            } else if (!strA.equals("custom_event")) {
                return;
            }
        } else if (!strA.equals("open")) {
            return;
        }
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.triggers.actions.j(event, 3), 7, (Object) null);
        com.braze.events.e eVar = this.d;
        if (eVar != null) {
            String strA2 = event.a();
            Intrinsics.checkNotNullExpressionValue(strA2, "getTriggerEventType(...)");
            ((com.braze.events.d) eVar).b(new NoMatchingTriggerEvent(strA2), NoMatchingTriggerEvent.class);
            return;
        }
        Intrinsics.m("externalEventMessenger");
        throw null;
    }

    public static final String a(com.braze.triggers.actions.a aVar) {
        return d0.r(new StringBuilder("Found potential triggered action for incoming trigger event. Action id "), ((com.braze.triggers.actions.g) aVar).a, '.');
    }

    public static final String a(com.braze.triggers.events.b bVar, J j) {
        String prettyPrintedString;
        StringBuilder sb = new StringBuilder("\n     Found best triggered action for incoming trigger event ");
        com.braze.models.i iVar = ((com.braze.triggers.events.i) bVar).c;
        if (iVar != null) {
            prettyPrintedString = JsonUtils.getPrettyPrintedString(((com.braze.models.outgoing.event.b) iVar).forJsonPut());
        } else {
            prettyPrintedString = "";
        }
        sb.append(prettyPrintedString);
        sb.append(".\n     Matched Action id: ");
        sb.append(((com.braze.triggers.actions.g) ((com.braze.triggers.actions.a) j.a)).a);
        sb.append(".\n                ");
        return x.c(sb.toString());
    }

    public final boolean a() {
        com.braze.requests.framework.b bVar = (com.braze.requests.framework.b) this.o.e.get(com.braze.requests.m.f);
        if (bVar == null || !(bVar instanceof com.braze.requests.framework.queue.c)) {
            return false;
        }
        ArrayList arrayList = ((com.braze.requests.framework.queue.c) bVar).e;
        if (arrayList != null && arrayList.isEmpty()) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            com.braze.requests.framework.h hVar = (com.braze.requests.framework.h) it2.next();
            com.braze.requests.n nVar = hVar.a;
            if ((nVar instanceof com.braze.requests.f) && ((com.braze.requests.f) nVar).j.b() && hVar.d == com.braze.requests.framework.i.c) {
                return true;
            }
        }
        return false;
    }
}
