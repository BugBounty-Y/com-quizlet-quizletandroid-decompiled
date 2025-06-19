package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.lifecycle.C1247h;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class i0 {
    public final ReentrantLock a;
    public final ArrayList b;
    public final SharedPreferences c;

    public i0(Context context, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        ReentrantLock reentrantLock = new ReentrantLock();
        this.a = reentrantLock;
        ArrayList arrayList = new ArrayList();
        this.b = arrayList;
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.storage.braze_push_delivery_storage", null, apiKey);
        this.c = sharedPreferencesG;
        reentrantLock.lock();
        try {
            arrayList.clear();
            Map<String, ?> all = sharedPreferencesG.getAll();
            Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
            Iterator<Map.Entry<String, ?>> it2 = all.entrySet().iterator();
            while (it2.hasNext()) {
                String key = it2.next().getKey();
                ArrayList arrayList2 = this.b;
                Intrinsics.d(key);
                arrayList2.add(new com.braze.models.push.a(key, this.c.getLong(key, 0L)));
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String a(List list) {
        return "Re-adding PDEs to storage: " + list;
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Adding push campaign to storage with uid ", str);
    }

    public final void a(String pushCampaignId) throws Throwable {
        Intrinsics.checkNotNullParameter(pushCampaignId, "pushCampaignId");
        ReentrantLock reentrantLock = this.a;
        reentrantLock.lock();
        try {
            try {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(pushCampaignId, 9), 7, (Object) null);
                long jNowInSeconds = DateTimeUtils.nowInSeconds();
                this.c.edit().putLong(pushCampaignId, jNowInSeconds).apply();
                this.b.add(new com.braze.models.push.a(pushCampaignId, jNowInSeconds));
                reentrantLock.unlock();
            } catch (Throwable th) {
                th = th;
                Throwable th2 = th;
                reentrantLock.unlock();
                throw th2;
            }
        } catch (Throwable th3) {
            th = th3;
        }
    }

    public final void b(ArrayList events) {
        Intrinsics.checkNotNullParameter(events, "events");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.k(2, events), 7, (Object) null);
        ReentrantLock reentrantLock = this.a;
        reentrantLock.lock();
        try {
            this.b.addAll(events);
        } finally {
            reentrantLock.unlock();
        }
    }

    public final void a(ArrayList events) throws Throwable {
        Intrinsics.checkNotNullParameter(events, "events");
        ReentrantLock reentrantLock = this.a;
        reentrantLock.lock();
        try {
            SharedPreferences.Editor editorEdit = this.c.edit();
            Iterator it2 = events.iterator();
            while (it2.hasNext()) {
                com.braze.models.push.a aVar = (com.braze.models.push.a) it2.next();
                try {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(aVar, 20), 7, (Object) null);
                    String string = aVar.b.getString("cid");
                    Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                    editorEdit.remove(string);
                } catch (Throwable th) {
                    th = th;
                    Throwable th2 = th;
                    reentrantLock.unlock();
                    throw th2;
                }
            }
            editorEdit.apply();
            this.b.removeAll(events);
            reentrantLock.unlock();
        } catch (Throwable th3) {
            th = th3;
        }
    }

    public static final String a(com.braze.models.push.a aVar) throws JSONException {
        StringBuilder sb = new StringBuilder("Clearing PDE from storage with uid ");
        String string = aVar.b.getString("cid");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        sb.append(string);
        return sb.toString();
    }
}
