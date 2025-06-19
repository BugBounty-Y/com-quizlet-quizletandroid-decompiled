package com.braze.triggers.managers;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1477c;
import com.braze.C1510p;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.w;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final SharedPreferences a;
    public final ConcurrentHashMap b;
    public final LinkedHashMap c;

    public g(Context context, String str, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.appboy.storage.triggers.re_eligibility", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.a = sharedPreferencesG;
        this.b = a();
        this.c = new LinkedHashMap();
    }

    public static final String a(String str) {
        return AbstractC1475a.a("Deleting outdated triggered action id ", str, " from stored re-eligibility list. In-memory re-eligibility list is unchanged.");
    }

    public static final String b(String str) {
        return AbstractC1475a.a("Retaining triggered action ", str, " in re-eligibility list.");
    }

    public static final String c(String str) {
        return AbstractC1475a.a("Retrieving triggered action id ", str, " eligibility information from local storage.");
    }

    public final void d(com.braze.triggers.actions.a triggeredAction) {
        Intrinsics.checkNotNullParameter(triggeredAction, "triggeredAction");
        com.braze.triggers.actions.g gVar = (com.braze.triggers.actions.g) triggeredAction;
        if (gVar.b.f.a == -1) {
            this.b.remove(gVar.a);
            this.a.edit().remove(gVar.a).apply();
            return;
        }
        Long l = (Long) this.c.get(gVar.a);
        long jLongValue = l != null ? l.longValue() : 0L;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new l(triggeredAction, jLongValue, 1), 7, (Object) null);
        this.b.put(gVar.a, Long.valueOf(jLongValue));
        this.a.edit().putLong(gVar.a, jLongValue).apply();
    }

    public static final String b(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Triggered action id "), ((com.braze.triggers.actions.g) aVar).a, " always eligible via never having been triggered. Returning true for eligibility status");
    }

    public static final String c(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Triggered action id "), ((com.braze.triggers.actions.g) aVar).a, " no longer eligible due to having been triggered in the past and is only eligible once.");
    }

    public final boolean a(com.braze.triggers.actions.g triggeredAction) {
        Intrinsics.checkNotNullParameter(triggeredAction, "triggeredAction");
        final com.braze.triggers.config.b bVar = triggeredAction.b.f;
        if (bVar.a == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new m(triggeredAction, 1), 7, (Object) null);
            return true;
        }
        if (!this.b.containsKey(triggeredAction.a)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new m(triggeredAction, 2), 7, (Object) null);
            return true;
        }
        if (bVar.a == -1) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new m(triggeredAction, 3), 7, (Object) null);
            return false;
        }
        Long l = (Long) this.b.get(triggeredAction.a);
        final long jLongValue = l != null ? l.longValue() : 0L;
        long jNowInSeconds = DateTimeUtils.nowInSeconds() + triggeredAction.b.d;
        int i = bVar.a;
        if (jNowInSeconds >= ((i > 0 ? Integer.valueOf(i) : null) != null ? r0.intValue() : 0) + jLongValue) {
            final int i2 = 0;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, new Function0() { // from class: com.braze.triggers.managers.n
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i2) {
                        case 0:
                            return g.a(jLongValue, bVar);
                        default:
                            return g.b(jLongValue, bVar);
                    }
                }
            }, 7, (Object) null);
            return true;
        }
        final int i3 = 1;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, new Function0() { // from class: com.braze.triggers.managers.n
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        return g.a(jLongValue, bVar);
                    default:
                        return g.b(jLongValue, bVar);
                }
            }
        }, 7, (Object) null);
        return false;
    }

    public static final String b(long j, com.braze.triggers.config.a aVar) {
        StringBuilder sb = new StringBuilder("Trigger action is not re-eligible for display since only ");
        sb.append(DateTimeUtils.nowInSeconds() - j);
        sb.append(" seconds have passed since the last time it was triggered (minimum interval: ");
        int i = ((com.braze.triggers.config.b) aVar).a;
        return assistantMode.refactored.a.l(sb, i > 0 ? Integer.valueOf(i) : null, ").");
    }

    public static final String b(com.braze.triggers.actions.a aVar, long j) {
        return "Resetting re-eligibility for action Id " + ((com.braze.triggers.actions.g) aVar).a + " to " + j;
    }

    public static final String b() {
        return "Encountered unexpected exception while parsing stored re-eligibility information.";
    }

    public static final String a(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Triggered action id "), ((com.braze.triggers.actions.g) aVar).a, " always eligible via configuration. Returning true for eligibility status");
    }

    public static final String a(long j, com.braze.triggers.config.a aVar) {
        StringBuilder sb = new StringBuilder("Trigger action is re-eligible for display since ");
        sb.append(DateTimeUtils.nowInSeconds() - j);
        sb.append(" seconds have passed since the last time it was triggered (minimum interval: ");
        int i = ((com.braze.triggers.config.b) aVar).a;
        return assistantMode.refactored.a.l(sb, i > 0 ? Integer.valueOf(i) : null, ").");
    }

    public final void a(com.braze.triggers.actions.h triggeredAction, long j) {
        Intrinsics.checkNotNullParameter(triggeredAction, "triggeredAction");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1510p(triggeredAction, j, 3), 7, (Object) null);
        LinkedHashMap linkedHashMap = this.c;
        String str = triggeredAction.a;
        Long l = (Long) this.b.get(str);
        linkedHashMap.put(str, Long.valueOf(l != null ? l.longValue() : 0L));
        this.b.put(triggeredAction.a, Long.valueOf(j));
        this.a.edit().putLong(triggeredAction.a, j).apply();
    }

    public static final String a(com.braze.triggers.actions.a aVar, long j) {
        return "Updating re-eligibility for action Id " + ((com.braze.triggers.actions.g) aVar).a + " to time " + j + '.';
    }

    public final ConcurrentHashMap a() {
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        try {
            for (String str : this.a.getAll().keySet()) {
                long j = this.a.getLong(str, 0L);
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 19), 7, (Object) null);
                concurrentHashMap.put(str, Long.valueOf(j));
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new i(11), 4, (Object) null);
        }
        return concurrentHashMap;
    }

    public final void a(List triggeredActions) {
        Intrinsics.checkNotNullParameter(triggeredActions, "triggeredActions");
        ArrayList arrayList = new ArrayList(C.q(triggeredActions, 10));
        Iterator it2 = triggeredActions.iterator();
        while (it2.hasNext()) {
            arrayList.add(((com.braze.triggers.actions.g) ((com.braze.triggers.actions.a) it2.next())).a);
        }
        SharedPreferences.Editor editorEdit = this.a.edit();
        for (String str : CollectionsKt.A0(this.b.keySet())) {
            if (!arrayList.contains(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 20), 7, (Object) null);
                editorEdit.remove(str);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 21), 7, (Object) null);
            }
        }
        editorEdit.apply();
    }
}
