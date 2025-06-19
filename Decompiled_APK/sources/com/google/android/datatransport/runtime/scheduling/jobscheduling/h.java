package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import androidx.camera.camera2.internal.C0128e;
import androidx.work.impl.CallableC1432d;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.android.billingclient.api.Purchase;
import com.braze.H;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.SubscriptionRequest;
import io.reactivex.rxjava3.core.o;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements com.google.android.datatransport.runtime.synchronization.a, com.google.firebase.concurrent.f, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ h(i iVar, Iterable iterable, com.google.android.datatransport.runtime.i iVar2, long j) {
        this.a = 0;
        this.c = iVar;
        this.d = iterable;
        this.e = iVar2;
        this.b = j;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        i iVar = (i) this.c;
        com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) iVar.c;
        gVar.getClass();
        Iterable iterable = (Iterable) this.d;
        if (iterable.iterator().hasNext()) {
            String str = "UPDATE events SET num_attempts = num_attempts + 1 WHERE _id in " + com.google.android.datatransport.runtime.scheduling.persistence.g.p(iterable);
            SQLiteDatabase sQLiteDatabaseA = gVar.a();
            sQLiteDatabaseA.beginTransaction();
            try {
                sQLiteDatabaseA.compileStatement(str).execute();
                Cursor cursorRawQuery = sQLiteDatabaseA.rawQuery("SELECT COUNT(*), transport_name FROM events WHERE num_attempts >= 16 GROUP BY transport_name", null);
                while (cursorRawQuery.moveToNext()) {
                    try {
                        gVar.j(cursorRawQuery.getInt(0), com.google.android.datatransport.runtime.firebase.transport.c.MAX_RETRIES_REACHED, cursorRawQuery.getString(1));
                    } catch (Throwable th) {
                        cursorRawQuery.close();
                        throw th;
                    }
                }
                cursorRawQuery.close();
                sQLiteDatabaseA.compileStatement("DELETE FROM events WHERE num_attempts >= 16").execute();
                sQLiteDatabaseA.setTransactionSuccessful();
            } finally {
                sQLiteDatabaseA.endTransaction();
            }
        }
        gVar.f(new C0128e(iVar.g.e() + this.b, (com.google.android.datatransport.runtime.i) this.e, 1));
        return null;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.data.model.billing.a details = (com.quizlet.data.model.billing.a) obj;
        com.quizlet.billing.subscriptions.h hVar = (com.quizlet.billing.subscriptions.h) this.c;
        com.quizlet.data.repository.classfolder.e eVar = hVar.j;
        Intrinsics.checkNotNullParameter(details, "details");
        long j = this.b;
        eVar.p(new H(eVar, j, details, 5));
        com.quizlet.data.repository.achievements.h hVar2 = hVar.a;
        ((com.quizlet.features.emailconfirmation.logging.a) hVar2.d).a.D("upgrade_sync_to_api");
        String str = (String) this.e;
        if (str == null) {
            str = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        return new io.reactivex.rxjava3.internal.operators.single.d(((IQuizletApiClient) hVar2.a).h(new SubscriptionRequest(new com.google.mlkit.vision.documentscanner.internal.c((Purchase) this.d), new com.google.firebase.crashlytics.internal.settings.b(details), j, "android_".concat(str))).g(new com.quizlet.baserecyclerview.decoration.a(1)).g(new com.quizlet.baserecyclerview.decoration.a(2)).g(new com.quizlet.baserecyclerview.decoration.a(hVar2)), new com.quizlet.billing.subscriptions.a(hVar2, 0), 2).l((o) hVar2.b).h((o) hVar2.c);
    }

    @Override // com.google.firebase.concurrent.f
    public ScheduledFuture b(com.quizlet.data.repository.school.membership.a aVar) {
        switch (this.a) {
            case 1:
                com.google.firebase.concurrent.e eVar = (com.google.firebase.concurrent.e) this.c;
                return eVar.b.schedule(new com.google.firebase.concurrent.d(eVar, (Runnable) this.d, aVar, 1), this.b, (TimeUnit) this.e);
            default:
                com.google.firebase.concurrent.e eVar2 = (com.google.firebase.concurrent.e) this.c;
                return eVar2.b.schedule(new CallableC1432d(eVar2, (Callable) this.d, aVar, 1), this.b, (TimeUnit) this.e);
        }
    }

    public /* synthetic */ h(com.google.firebase.concurrent.e eVar, Object obj, long j, TimeUnit timeUnit, int i) {
        this.a = i;
        this.c = eVar;
        this.d = obj;
        this.b = j;
        this.e = timeUnit;
    }

    public /* synthetic */ h(com.quizlet.billing.subscriptions.h hVar, long j, Purchase purchase, String str) {
        this.a = 3;
        this.c = hVar;
        this.b = j;
        this.d = purchase;
        this.e = str;
    }
}
