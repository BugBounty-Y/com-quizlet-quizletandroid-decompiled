package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1484j;
import com.braze.events.IEventSubscriber;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class k0 {
    public final com.braze.storage.e0 a;
    public final SharedPreferences b;
    public final SharedPreferences c;

    public k0(Context context, String apiKey, String str, com.braze.events.d internalEventPublisher, com.braze.storage.e0 serverConfigStorageProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        this.a = serverConfigStorageProvider;
        SharedPreferences pushMaxPrefs = assistantMode.refactored.a.g(0, context, "com.braze.storage.braze_push_max_storage", str, apiKey);
        this.b = pushMaxPrefs;
        this.c = assistantMode.refactored.a.g(0, context, "com.braze.storage.braze_push_max_metadata", str, apiKey);
        internalEventPublisher.c(com.braze.events.internal.p.class, (IEventSubscriber) new com.braze.dispatch.m(this, 2));
        long jNowInSeconds = DateTimeUtils.nowInSeconds() - TimeUnit.DAYS.toSeconds(45L);
        Intrinsics.checkNotNullExpressionValue(pushMaxPrefs, "pushMaxPrefs");
        ArrayList arrayList = new ArrayList();
        Map<String, ?> all = pushMaxPrefs.getAll();
        Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
        Iterator<Map.Entry<String, ?>> it2 = all.entrySet().iterator();
        while (it2.hasNext()) {
            String key = it2.next().getKey();
            Intrinsics.d(key);
            arrayList.add(new j0(key, pushMaxPrefs.getLong(key, 0L)));
        }
        List<j0> listW0 = CollectionsKt.w0(arrayList);
        SharedPreferences.Editor editorEdit = pushMaxPrefs.edit();
        for (j0 j0Var : listW0) {
            if (this.b.getLong(j0Var.a, 0L) < jNowInSeconds) {
                editorEdit.remove(j0Var.a);
            }
        }
        editorEdit.apply();
    }

    public static final void a(k0 k0Var, com.braze.events.internal.p it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        k0Var.c.edit().putLong("lastUpdateTime", it2.a).apply();
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Adding push campaign to storage with uid ", str);
    }

    public final void a(String pushCampaign) {
        Intrinsics.checkNotNullParameter(pushCampaign, "pushCampaign");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(pushCampaign, 10), 7, (Object) null);
        if (StringsKt.O(pushCampaign)) {
            return;
        }
        this.b.edit().putLong(pushCampaign, DateTimeUtils.nowInSeconds()).apply();
    }

    public final void a() {
        this.b.edit().clear().apply();
        this.c.edit().clear().apply();
    }
}
