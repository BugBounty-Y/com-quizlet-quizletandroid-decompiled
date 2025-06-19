package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.lifecycle.C1247h;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.events.BannersUpdatedEvent;
import com.braze.events.BrazeUserChangeEvent;
import com.braze.events.IEventSubscriber;
import com.braze.models.Banner;
import com.braze.requests.C1512a;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.InterfaceC5025j0;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.braze.managers.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1495h {
    public static InterfaceC5025j0 m;
    public final String a;
    public final com.braze.events.e b;
    public final com.braze.storage.e0 c;
    public final C1500m d;
    public List e;
    public final AtomicBoolean f;
    public final SharedPreferences g;
    public final SharedPreferences h;
    public final SharedPreferences i;
    public final AtomicInteger j;
    public static final C1494g k = new C1494g();
    public static final LinkedHashMap l = new LinkedHashMap();
    public static final ReentrantLock n = new ReentrantLock();
    public static final ArrayList o = new ArrayList();
    public static final ReentrantLock p = new ReentrantLock();
    public static final ArrayList q = new ArrayList();

    public C1495h(Context context, String apiKey, String str, com.braze.events.e internalEventPublisher, com.braze.events.e externalEventPublisher, com.braze.storage.e0 serverConfigStorageProvider, C1500m brazeManager) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.a = str;
        this.b = externalEventPublisher;
        this.c = serverConfigStorageProvider;
        this.d = brazeManager;
        this.e = kotlin.collections.K.a;
        this.f = new AtomicBoolean(false);
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.managers.banners.eligibility", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.g = sharedPreferencesG;
        SharedPreferences sharedPreferencesG2 = assistantMode.refactored.a.g(0, context, "com.braze.managers.banners.storage", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG2, "getSharedPreferences(...)");
        this.h = sharedPreferencesG2;
        SharedPreferences sharedPreferencesG3 = assistantMode.refactored.a.g(0, context, "com.braze.managers.banners.impressions", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG3, "getSharedPreferences(...)");
        this.i = sharedPreferencesG3;
        this.j = new AtomicInteger(0);
        e();
        final int i = 0;
        com.braze.events.d dVar = (com.braze.events.d) internalEventPublisher;
        dVar.c(com.braze.events.internal.q.class, new IEventSubscriber(this) { // from class: com.braze.managers.F
            public final /* synthetic */ C1495h b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        C1495h.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 1:
                        C1495h.a(this.b, (com.braze.events.internal.c) obj);
                        break;
                    case 2:
                        C1495h.a(this.b, (com.braze.events.internal.b) obj);
                        break;
                    case 3:
                        C1495h.a(this.b, (BrazeUserChangeEvent) obj);
                        break;
                    default:
                        C1495h.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        dVar.c(com.braze.events.internal.c.class, new IEventSubscriber(this) { // from class: com.braze.managers.F
            public final /* synthetic */ C1495h b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        C1495h.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 1:
                        C1495h.a(this.b, (com.braze.events.internal.c) obj);
                        break;
                    case 2:
                        C1495h.a(this.b, (com.braze.events.internal.b) obj);
                        break;
                    case 3:
                        C1495h.a(this.b, (BrazeUserChangeEvent) obj);
                        break;
                    default:
                        C1495h.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i3 = 2;
        dVar.c(com.braze.events.internal.b.class, new IEventSubscriber(this) { // from class: com.braze.managers.F
            public final /* synthetic */ C1495h b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i3) {
                    case 0:
                        C1495h.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 1:
                        C1495h.a(this.b, (com.braze.events.internal.c) obj);
                        break;
                    case 2:
                        C1495h.a(this.b, (com.braze.events.internal.b) obj);
                        break;
                    case 3:
                        C1495h.a(this.b, (BrazeUserChangeEvent) obj);
                        break;
                    default:
                        C1495h.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i4 = 3;
        dVar.d(BrazeUserChangeEvent.class, new IEventSubscriber(this) { // from class: com.braze.managers.F
            public final /* synthetic */ C1495h b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i4) {
                    case 0:
                        C1495h.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 1:
                        C1495h.a(this.b, (com.braze.events.internal.c) obj);
                        break;
                    case 2:
                        C1495h.a(this.b, (com.braze.events.internal.b) obj);
                        break;
                    case 3:
                        C1495h.a(this.b, (BrazeUserChangeEvent) obj);
                        break;
                    default:
                        C1495h.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
        final int i5 = 4;
        dVar.c(com.braze.events.internal.d.class, new IEventSubscriber(this) { // from class: com.braze.managers.F
            public final /* synthetic */ C1495h b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i5) {
                    case 0:
                        C1495h.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    case 1:
                        C1495h.a(this.b, (com.braze.events.internal.c) obj);
                        break;
                    case 2:
                        C1495h.a(this.b, (com.braze.events.internal.b) obj);
                        break;
                    case 3:
                        C1495h.a(this.b, (BrazeUserChangeEvent) obj);
                        break;
                    default:
                        C1495h.a(this.b, (com.braze.events.internal.d) obj);
                        break;
                }
            }
        });
    }

    public static final void a(C1495h c1495h, com.braze.events.internal.d it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (!it2.a.F || it2.b.F) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c1495h, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(10), 7, (Object) null);
        c1495h.a();
    }

    public static final String b(BrazeUserChangeEvent brazeUserChangeEvent) {
        return "Done updating banners because of user change to " + brazeUserChangeEvent.getCurrentUserId() + '.';
    }

    public static final String c() {
        return "Refreshing Banners on forced internal refresh.";
    }

    public static final String d(String str) {
        return AbstractC1475a.a("Received null or blank serialized Banner string for Banner id ", str, " from shared preferences. Not parsing.");
    }

    public static final String e(String str) {
        return AbstractC1484j.a("Encountered unexpected exception while parsing stored banner: ", str);
    }

    public static final String f() {
        return "Did not find stored Banners.";
    }

    public static final String g() {
        return "Failed to find stored Banner keys.";
    }

    public static final String h() {
        return "Bypassing rate limit for Banner refresh.";
    }

    public static final String i() {
        return "Banners have already been sync'd. Only one sync per session is allowed.";
    }

    public static final String k() {
        return "Resetting BannersManager for new session.";
    }

    public static final String l() {
        return "Added new Banners to local storage.";
    }

    public final void j() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(12), 6, (Object) null);
        this.i.edit().clear().apply();
        this.f.set(false);
        C1494g.a();
    }

    public final void m() {
        ArrayList arrayList = new ArrayList();
        ReentrantLock reentrantLock = n;
        reentrantLock.lock();
        try {
            List listW0 = CollectionsKt.w0(o);
            Unit unit = Unit.a;
            reentrantLock.unlock();
            Iterator it2 = listW0.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                try {
                    throw null;
                } catch (Exception e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(17), 4, (Object) null);
                    arrayList.add(null);
                }
            }
            n.lock();
            try {
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    if (it3.next() != null) {
                        throw new ClassCastException();
                    }
                    o.remove((Object) null);
                }
                Unit unit2 = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        } finally {
            reentrantLock.unlock();
        }
    }

    public final void o() {
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.dispatch.j(2, jNowInSeconds), 6, (Object) null);
        this.g.edit().putLong("last_refresh", jNowInSeconds).apply();
    }

    public static final String b() {
        return "Cached Banners placement IDs are empty. Not refreshing Banners on forced internal call.";
    }

    public static final String c(Banner banner) {
        return "Not storing expired Banner: " + banner + ". The Banner's expiration timestamp is in the past.";
    }

    public static final String d() {
        return "Banners have moved to disabled. Clearing banners data.";
    }

    public final void e() {
        SharedPreferences sharedPreferences = this.h;
        ArrayList arrayList = new ArrayList();
        Map<String, ?> all = sharedPreferences.getAll();
        if (all == null || all.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(9), 7, (Object) null);
            this.e = kotlin.collections.K.a;
            return;
        }
        Set<String> setKeySet = all.keySet();
        if (setKeySet.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new D(18), 6, (Object) null);
            this.e = kotlin.collections.K.a;
            return;
        }
        for (String str : setKeySet) {
            String str2 = (String) all.get(str);
            if (str2 != null) {
                try {
                } catch (Exception e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(str2, 5), 4, (Object) null);
                    Unit unit = Unit.a;
                }
                if (!StringsKt.O(str2)) {
                    Banner bannerA = Banner.Companion.a(new JSONObject(str2));
                    if (bannerA != null) {
                        arrayList.add(bannerA);
                    }
                }
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(str, 4), 6, (Object) null);
        }
        this.e = arrayList;
    }

    public static final String b(AbstractC1491d abstractC1491d) {
        throw null;
    }

    public static final String d(Banner banner) {
        return "Error storing Banner: " + banner + '.';
    }

    public static final void a(C1495h c1495h, com.braze.events.internal.q it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (it2.a instanceof C1512a) {
            c1495h.j.decrementAndGet();
        }
    }

    public static final void a(C1495h c1495h, com.braze.events.internal.c it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        c1495h.f.set(true);
        c1495h.o();
    }

    public static final void a(C1495h c1495h, com.braze.events.internal.b it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        ((com.braze.events.d) c1495h.b).b(it2, com.braze.events.internal.b.class);
    }

    public static final void a(C1495h c1495h, BrazeUserChangeEvent it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) c1495h, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new G(it2, 0), 7, (Object) null);
        c1495h.m();
        BrazeLogger.brazelog$default(brazeLogger, (Object) c1495h, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new G(it2, 1), 7, (Object) null);
    }

    public static final String a(BrazeUserChangeEvent brazeUserChangeEvent) {
        return "Updating banners because of user change to " + brazeUserChangeEvent.getCurrentUserId() + '.';
    }

    public final void a(boolean z) {
        ReentrantLock reentrantLock = p;
        reentrantLock.lock();
        try {
            ArrayList arrayListY0 = CollectionsKt.y0(q);
            reentrantLock.unlock();
            if (arrayListY0.isEmpty()) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(13), 7, (Object) null);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(14), 7, (Object) null);
                a(arrayListY0, z);
            }
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean a(List ids, boolean z) {
        String trackingId;
        Object next;
        Intrinsics.checkNotNullParameter(ids, "ids");
        if (this.j.get() > 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(this, 19), 7, (Object) null);
            return false;
        }
        if (z) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(15), 7, (Object) null);
        } else if (this.f.get()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(16), 6, (Object) null);
            return false;
        }
        if (ids.size() > this.c.p()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(7, this, ids), 7, (Object) null);
        }
        this.j.incrementAndGet();
        List<String> ids2 = CollectionsKt.p0(ids, this.c.p());
        Intrinsics.checkNotNullParameter(ids2, "ids");
        ArrayList arrayList = new ArrayList();
        for (String str : ids2) {
            Iterator it2 = this.e.iterator();
            while (true) {
                trackingId = null;
                if (!it2.hasNext()) {
                    next = null;
                    break;
                }
                next = it2.next();
                if (Intrinsics.b(((Banner) next).getPlacementId(), str)) {
                    break;
                }
            }
            Banner banner = (Banner) next;
            if (banner != null) {
                trackingId = banner.getTrackingId();
            }
            arrayList.add(new Pair(str, trackingId));
        }
        this.d.a(arrayList);
        return true;
    }

    public final void a() {
        this.e = kotlin.collections.K.a;
        this.h.edit().clear().apply();
        m();
    }

    public static final String a(C1495h c1495h) {
        return "Not refreshing Banners since another " + c1495h.j.get() + " request is currently in-flight.";
    }

    public static final String a(C1495h c1495h, List list) {
        return "The number of Banner placements requested exceeds the maximum allowed by the server. The server allows a maximum of " + c1495h.c.p() + " placements, but " + list.size() + " were requested. Truncating request to fit.\nPlacements that will be requested: " + CollectionsKt.p0(list, c1495h.c.p()) + "\nTruncated placements not requested: " + list.subList(c1495h.c.p(), list.size());
    }

    public final BannersUpdatedEvent a(JSONObject bannersJson) throws JSONException {
        Intrinsics.checkNotNullParameter(bannersJson, "bannerData");
        Banner.Companion.getClass();
        Intrinsics.checkNotNullParameter(bannersJson, "bannersJson");
        ArrayList arrayList = new ArrayList();
        Iterator<String> itKeys = bannersJson.keys();
        Intrinsics.checkNotNullExpressionValue(itKeys, "keys(...)");
        while (itKeys.hasNext()) {
            Banner bannerA = Banner.Companion.a(bannersJson.optJSONObject(itKeys.next()));
            if (bannerA != null) {
                arrayList.add(bannerA);
            }
        }
        ArrayList<Banner> arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((Banner) next).isTestSend()) {
                arrayList2.add(next);
            } else {
                arrayList3.add(next);
            }
        }
        for (Banner banner : arrayList2) {
            l.put(banner.getPlacementId(), banner);
        }
        this.e = arrayList3;
        SharedPreferences.Editor editorEdit = this.h.edit();
        editorEdit.clear();
        for (final Banner banner2 : this.e) {
            if (banner2.isExpired()) {
                final int i = 0;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, new Function0() { // from class: com.braze.managers.H
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i) {
                            case 0:
                                return C1495h.c(banner2);
                            default:
                                return C1495h.d(banner2);
                        }
                    }
                }, 6, (Object) null);
            } else {
                try {
                    editorEdit.putString(banner2.getPlacementId(), banner2.forJsonPut().toString());
                } catch (Exception e) {
                    final int i2 = 1;
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, new Function0() { // from class: com.braze.managers.H
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i2) {
                                case 0:
                                    return C1495h.c(banner2);
                                default:
                                    return C1495h.d(banner2);
                            }
                        }
                    }, 4, (Object) null);
                }
            }
        }
        editorEdit.apply();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(11), 7, (Object) null);
        m();
        List list = this.e;
        ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            arrayList4.add(((Banner) it3.next()).deepcopy$android_sdk_base_release());
        }
        return new BannersUpdatedEvent(arrayList4);
    }

    public static final String a(long j) {
        return androidx.compose.animation.d0.n(j, "Updating last Banners refresh time: ");
    }
}
