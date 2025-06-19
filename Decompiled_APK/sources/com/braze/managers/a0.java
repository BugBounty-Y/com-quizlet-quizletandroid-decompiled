package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.lifecycle.C1247h;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.C1510p;
import com.braze.events.FeatureFlagsUpdatedEvent;
import com.braze.events.IEventSubscriber;
import com.braze.models.FeatureFlag;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a0 {
    public final com.braze.events.e a;
    public final com.braze.events.e b;
    public final com.braze.storage.e0 c;
    public final C1500m d;
    public List e;
    public final AtomicBoolean f;
    public final SharedPreferences g;
    public final SharedPreferences h;
    public final SharedPreferences i;
    public final AtomicInteger j;

    public a0(Context context, String apiKey, String str, com.braze.events.e internalEventPublisher, com.braze.events.e externalEventPublisher, com.braze.storage.e0 serverConfigStorageProvider, C1500m brazeManager) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.a = internalEventPublisher;
        this.b = externalEventPublisher;
        this.c = serverConfigStorageProvider;
        this.d = brazeManager;
        this.e = kotlin.collections.K.a;
        this.f = new AtomicBoolean(false);
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.managers.featureflags.eligibility", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.g = sharedPreferencesG;
        SharedPreferences sharedPreferencesG2 = assistantMode.refactored.a.g(0, context, "com.braze.managers.featureflags.storage", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG2, "getSharedPreferences(...)");
        this.h = sharedPreferencesG2;
        SharedPreferences sharedPreferencesG3 = assistantMode.refactored.a.g(0, context, "com.braze.managers.featureflags.impressions", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG3, "getSharedPreferences(...)");
        this.i = sharedPreferencesG3;
        this.j = new AtomicInteger(0);
        c();
        h();
    }

    public static final String a(String str) {
        return AbstractC1475a.a("Received null or blank serialized Feature Flag string for Feature Flag id ", str, " from shared preferences. Not parsing.");
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Encountered unexpected exception while parsing stored feature flags: ", str);
    }

    public static final String d() {
        return "Did not find stored Feature Flags.";
    }

    public static final String e() {
        return "Failed to find stored Feature Flag keys.";
    }

    public static final String i() {
        return "Features flags have moved to disabled. Clearing feature flag data.";
    }

    public static final String j() {
        return "Added new Feature Flags to local storage.";
    }

    public final void c() {
        SharedPreferences sharedPreferences = this.h;
        ArrayList arrayList = new ArrayList();
        Map<String, ?> all = sharedPreferences.getAll();
        if (all == null || all.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(25), 7, (Object) null);
            this.e = kotlin.collections.K.a;
            return;
        }
        Set<String> setKeySet = all.keySet();
        if (setKeySet.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new A(24), 6, (Object) null);
            this.e = kotlin.collections.K.a;
            return;
        }
        for (String str : setKeySet) {
            String str2 = (String) all.get(str);
            if (str2 != null) {
                try {
                } catch (Exception e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(str2, 1), 4, (Object) null);
                    Unit unit = Unit.a;
                }
                if (!StringsKt.O(str2)) {
                    FeatureFlag featureFlagA = com.braze.support.i.a.a(new JSONObject(str2));
                    if (featureFlagA != null) {
                        arrayList.add(featureFlagA);
                    }
                }
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(str, 0), 6, (Object) null);
        }
        this.e = arrayList;
    }

    public final void f() {
        if (this.j.get() > 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(this, 16), 7, (Object) null);
            return;
        }
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        if (jNowInSeconds - this.g.getLong("last_refresh", 0L) >= this.c.m()) {
            this.d.w();
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1510p(this, jNowInSeconds, 1), 6, (Object) null);
        ((com.braze.events.d) this.a).b(new com.braze.events.internal.j(), com.braze.events.internal.j.class);
    }

    public final void g() {
        this.i.edit().clear().apply();
    }

    public final void h() {
        final int i = 0;
        ((com.braze.events.d) this.a).c(com.braze.events.internal.r.class, new IEventSubscriber(this) { // from class: com.braze.managers.B
            public final /* synthetic */ a0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        a0.a(this.b, (com.braze.events.internal.r) obj);
                        break;
                    case 1:
                        a0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 2:
                        a0.a(this.b, (com.braze.events.internal.k) obj);
                        break;
                    case 3:
                        a0.a(this.b, (com.braze.events.internal.j) obj);
                        break;
                    default:
                        a0.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        ((com.braze.events.d) this.a).c(com.braze.events.internal.q.class, new IEventSubscriber(this) { // from class: com.braze.managers.B
            public final /* synthetic */ a0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        a0.a(this.b, (com.braze.events.internal.r) obj);
                        break;
                    case 1:
                        a0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 2:
                        a0.a(this.b, (com.braze.events.internal.k) obj);
                        break;
                    case 3:
                        a0.a(this.b, (com.braze.events.internal.j) obj);
                        break;
                    default:
                        a0.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i3 = 2;
        ((com.braze.events.d) this.a).c(com.braze.events.internal.k.class, new IEventSubscriber(this) { // from class: com.braze.managers.B
            public final /* synthetic */ a0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i3) {
                    case 0:
                        a0.a(this.b, (com.braze.events.internal.r) obj);
                        break;
                    case 1:
                        a0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 2:
                        a0.a(this.b, (com.braze.events.internal.k) obj);
                        break;
                    case 3:
                        a0.a(this.b, (com.braze.events.internal.j) obj);
                        break;
                    default:
                        a0.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i4 = 3;
        ((com.braze.events.d) this.a).c(com.braze.events.internal.j.class, new IEventSubscriber(this) { // from class: com.braze.managers.B
            public final /* synthetic */ a0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i4) {
                    case 0:
                        a0.a(this.b, (com.braze.events.internal.r) obj);
                        break;
                    case 1:
                        a0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 2:
                        a0.a(this.b, (com.braze.events.internal.k) obj);
                        break;
                    case 3:
                        a0.a(this.b, (com.braze.events.internal.j) obj);
                        break;
                    default:
                        a0.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i5 = 4;
        ((com.braze.events.d) this.a).c(com.braze.events.internal.d.class, new IEventSubscriber(this) { // from class: com.braze.managers.B
            public final /* synthetic */ a0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i5) {
                    case 0:
                        a0.a(this.b, (com.braze.events.internal.r) obj);
                        break;
                    case 1:
                        a0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 2:
                        a0.a(this.b, (com.braze.events.internal.k) obj);
                        break;
                    case 3:
                        a0.a(this.b, (com.braze.events.internal.j) obj);
                        break;
                    default:
                        a0.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
    }

    public final void k() {
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.dispatch.j(1, jNowInSeconds), 6, (Object) null);
        this.g.edit().putLong("last_refresh", jNowInSeconds).apply();
    }

    public static final String b(FeatureFlag featureFlag) {
        return "Error storing Feature Flag: " + featureFlag + '.';
    }

    public final FeatureFlagsUpdatedEvent a(JSONArray featureFlagsJson) throws JSONException {
        Intrinsics.checkNotNullParameter(featureFlagsJson, "featureFlagsData");
        Intrinsics.checkNotNullParameter(featureFlagsJson, "featureFlagsJson");
        ArrayList arrayList = new ArrayList();
        kotlin.sequences.t tVarH = kotlin.sequences.q.h(kotlin.sequences.q.e(CollectionsKt.D(kotlin.ranges.l.h(0, featureFlagsJson.length())), new com.braze.support.g(featureFlagsJson)), new com.braze.support.h(featureFlagsJson));
        Iterator it2 = tVarH.b.iterator();
        while (it2.hasNext()) {
            FeatureFlag featureFlagA = com.braze.support.i.a.a((JSONObject) tVarH.c.invoke(it2.next()));
            if (featureFlagA != null) {
                arrayList.add(featureFlagA);
            }
        }
        this.e = arrayList;
        SharedPreferences.Editor editorEdit = this.h.edit();
        editorEdit.clear();
        for (FeatureFlag featureFlag : this.e) {
            try {
                editorEdit.putString(featureFlag.getId(), featureFlag.forJsonPut().toString());
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C1247h(featureFlag, 15), 4, (Object) null);
            }
        }
        editorEdit.apply();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(23), 7, (Object) null);
        List list = this.e;
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            arrayList2.add(((FeatureFlag) it3.next()).deepcopy$android_sdk_base_release());
        }
        return new FeatureFlagsUpdatedEvent(arrayList2);
    }

    public static final String b() {
        return "Clearing Feature Flags.";
    }

    public static final void a(a0 a0Var, com.braze.events.internal.d it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (!it2.a.m || it2.b.m) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a0Var, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(22), 7, (Object) null);
        a0Var.a();
    }

    public static final void a(a0 a0Var, com.braze.events.internal.r it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (it2.a instanceof com.braze.requests.i) {
            a0Var.j.incrementAndGet();
        }
    }

    public static final void a(a0 a0Var, com.braze.events.internal.q it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (it2.a instanceof com.braze.requests.i) {
            a0Var.j.decrementAndGet();
        }
    }

    public static final void a(a0 a0Var, com.braze.events.internal.k it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        a0Var.f.set(true);
        a0Var.k();
    }

    public static final void a(a0 a0Var, com.braze.events.internal.j it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        a0Var.f.set(true);
        if (a0Var.f.get()) {
            List list = a0Var.e;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            Iterator it3 = list.iterator();
            while (it3.hasNext()) {
                arrayList.add(((FeatureFlag) it3.next()).deepcopy$android_sdk_base_release());
            }
            ((com.braze.events.d) a0Var.b).b(new FeatureFlagsUpdatedEvent(arrayList), FeatureFlagsUpdatedEvent.class);
        }
    }

    public static final String a(a0 a0Var) {
        return "Not refreshing Feature Flags since another " + a0Var.j.get() + " request is currently in-flight.";
    }

    public static final String a(a0 a0Var, long j) {
        return android.support.v4.media.session.a.g((a0Var.g.getLong("last_refresh", 0L) - j) + a0Var.c.m(), " seconds remaining until next available flush.", new StringBuilder("Not enough time has passed since last Feature Flags refresh. Not refreshing Feature Flags. "));
    }

    public static final String a(long j) {
        return androidx.compose.animation.d0.n(j, "Updating last Feature Flags refresh time: ");
    }

    public final void a() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(21), 7, (Object) null);
        this.h.edit().clear().apply();
        this.e = kotlin.collections.K.a;
        if (this.f.get()) {
            List list = this.e;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(((FeatureFlag) it2.next()).deepcopy$android_sdk_base_release());
            }
            ((com.braze.events.d) this.b).b(new FeatureFlagsUpdatedEvent(arrayList), FeatureFlagsUpdatedEvent.class);
        }
    }
}
