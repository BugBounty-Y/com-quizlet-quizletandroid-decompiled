package androidx.camera.core.impl.utils.futures;

import android.content.ContentValues;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.text.TextUtils;
import android.util.Log;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.C0128e;
import androidx.compose.animation.d0;
import com.android.billingclient.api.Purchase;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.google.android.gms.tasks.Task;
import com.google.firebase.crashlytics.internal.model.C3947l0;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import java.util.HashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements androidx.concurrent.futures.j, com.google.android.datatransport.runtime.synchronization.a, com.google.android.datatransport.runtime.scheduling.persistence.e, com.google.firebase.inject.a, com.google.android.gms.tasks.a, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ e(Object obj, long j, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
        this.d = obj2;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        com.google.android.datatransport.runtime.scheduling.jobscheduling.i iVar = (com.google.android.datatransport.runtime.scheduling.jobscheduling.i) this.c;
        long jE = iVar.g.e() + this.b;
        com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) iVar.c;
        com.google.android.datatransport.runtime.i iVar2 = (com.google.android.datatransport.runtime.i) this.d;
        gVar.getClass();
        gVar.f(new C0128e(jE, iVar2, 1));
        return null;
    }

    @Override // com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) throws SQLException {
        switch (this.a) {
            case 2:
                SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
                int i = ((com.google.android.datatransport.runtime.firebase.transport.c) this.d).a;
                String string = Integer.toString(i);
                String str = (String) this.c;
                Cursor cursorRawQuery = sQLiteDatabase.rawQuery("SELECT 1 FROM log_event_dropped WHERE log_source = ? AND reason = ?", new String[]{str, string});
                try {
                    boolean z = cursorRawQuery.getCount() > 0;
                    cursorRawQuery.close();
                    long j = this.b;
                    if (z) {
                        sQLiteDatabase.execSQL(d0.o(j, "UPDATE log_event_dropped SET events_dropped_count = events_dropped_count + ", " WHERE log_source = ? AND reason = ?"), new String[]{str, Integer.toString(i)});
                    } else {
                        ContentValues contentValues = new ContentValues();
                        contentValues.put("log_source", str);
                        contentValues.put("reason", Integer.valueOf(i));
                        contentValues.put("events_dropped_count", Long.valueOf(j));
                        sQLiteDatabase.insert("log_event_dropped", null, contentValues);
                    }
                    return null;
                } catch (Throwable th) {
                    cursorRawQuery.close();
                    throw th;
                }
            default:
                Purchase purchase = (Purchase) obj;
                com.quizlet.billing.subscriptions.h hVar = (com.quizlet.billing.subscriptions.h) this.c;
                hVar.getClass();
                String orderId = purchase.c.optString(DBTermFields.Names.RANK);
                if (TextUtils.isEmpty(orderId)) {
                    orderId = null;
                }
                com.quizlet.billing.register.a aVar = hVar.d;
                Intrinsics.checkNotNullParameter(orderId, "orderId");
                SharedPreferences.Editor editorEdit = aVar.a.edit();
                StringBuilder sb = new StringBuilder("register_");
                long j2 = this.b;
                sb.append(j2);
                editorEdit.putString(sb.toString(), orderId).apply();
                return new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.billing.subscriptions.e(j2, purchase, hVar, AbstractC3722s6.d(purchase), (String) this.d), 4);
        }
    }

    @Override // androidx.concurrent.futures.j
    public Object d(final androidx.concurrent.futures.i iVar) {
        final com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) this.c;
        i.e(true, eVar, iVar, T.a());
        if (!eVar.isDone()) {
            final long j = this.b;
            eVar.a(new RunnableC0041m(((androidx.camera.core.impl.utils.executor.e) this.d).schedule(new Callable() { // from class: androidx.camera.core.impl.utils.futures.f
                @Override // java.util.concurrent.Callable
                public final Object call() {
                    return Boolean.valueOf(iVar.d(new TimeoutException("Future[" + eVar + "] is not done within " + j + " ms.")));
                }
            }, j, TimeUnit.MILLISECONDS), 16), T.a());
        }
        return "TimeoutFuture[" + eVar + "]";
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        return ((com.google.firebase.remoteconfig.internal.e) this.c).b(task, this.b, (HashMap) this.d);
    }

    @Override // com.google.firebase.inject.a
    public void i(com.google.firebase.inject.b bVar) {
        com.google.firebase.crashlytics.internal.a aVar = (com.google.firebase.crashlytics.internal.a) bVar.get();
        C3947l0 c3947l0 = (C3947l0) this.d;
        aVar.getClass();
        Log.isLoggable("FirebaseCrashlytics", 2);
        aVar.a.a(new e((String) this.c, this.b, c3947l0, 3));
    }

    public /* synthetic */ e(Object obj, Object obj2, long j, int i) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.b = j;
    }
}
