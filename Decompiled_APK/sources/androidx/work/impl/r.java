package androidx.work.impl;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.os.Trace;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.compose.material3.internal.H;
import androidx.datastore.core.C1087t;
import androidx.lifecycle.C1247h;
import androidx.paging.J0;
import androidx.work.C1422c;
import androidx.work.P;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class r extends P {
    public static r k;
    public static r l;
    public static final Object m;
    public final Context a;
    public final C1422c b;
    public final WorkDatabase c;
    public final androidx.work.impl.utils.taskexecutor.c d;
    public final List e;
    public final C1433e f;
    public final com.google.firebase.platforminfo.c g;
    public boolean h = false;
    public BroadcastReceiver.PendingResult i;
    public final androidx.work.impl.constraints.trackers.j j;

    static {
        androidx.work.z.e("WorkManagerImpl");
        k = null;
        l = null;
        m = new Object();
    }

    public r(Context context, final C1422c configuration, androidx.work.impl.utils.taskexecutor.c taskExecutor, final WorkDatabase db, final List list, C1433e c1433e, androidx.work.impl.constraints.trackers.j jVar) {
        Context appContext = context.getApplicationContext();
        if (appContext.isDeviceProtectedStorage()) {
            throw new IllegalStateException("Cannot initialize WorkManager in direct boot mode");
        }
        androidx.work.z zVar = new androidx.work.z(configuration.h);
        synchronized (androidx.work.z.b) {
            try {
                if (androidx.work.z.c == null) {
                    androidx.work.z.c = zVar;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.a = appContext;
        this.d = taskExecutor;
        this.c = db;
        this.f = c1433e;
        this.j = jVar;
        this.b = configuration;
        this.e = list;
        Intrinsics.checkNotNullParameter(taskExecutor, "taskExecutor");
        AbstractC5040y abstractC5040y = taskExecutor.b;
        Intrinsics.checkNotNullExpressionValue(abstractC5040y, "taskExecutor.taskCoroutineDispatcher");
        kotlinx.coroutines.internal.d dVarC = kotlinx.coroutines.E.c(abstractC5040y);
        this.g = new com.google.firebase.platforminfo.c(db);
        final ExecutorC0060p executorC0060p = taskExecutor.a;
        int i = i.a;
        c1433e.a(new InterfaceC1430b() { // from class: androidx.work.impl.h
            @Override // androidx.work.impl.InterfaceC1430b
            public final void b(androidx.work.impl.model.j jVar2, boolean z) {
                executorC0060p.execute(new androidx.camera.camera2.internal.compat.b(list, jVar2, configuration, db, 4));
            }
        });
        taskExecutor.a(new androidx.work.impl.utils.c(appContext, this));
        String str = m.a;
        Intrinsics.checkNotNullParameter(dVarC, "<this>");
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(db, "db");
        if (androidx.work.impl.utils.i.a(appContext, configuration)) {
            androidx.work.impl.model.t tVarU = db.u();
            tVarU.getClass();
            androidx.work.impl.model.s sVar = new androidx.work.impl.model.s(tVarU, androidx.room.u.a(0, "SELECT COUNT(*) > 0 FROM workspec WHERE state NOT IN (2, 3, 5) LIMIT 1"), 1);
            int i2 = 18;
            e0.w(new J0(e0.m(e0.f(new H(i2, new C1087t(new androidx.room.e((WorkDatabase_Impl) tVarU.a, new String[]{"workspec"}, sVar, null)), new k(4, null)), -1)), new l(appContext, null), 5), dVarC);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x003c, code lost:
    
        r4 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x004b, code lost:
    
        throw r4;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.work.impl.r h(android.content.Context r4) {
        /*
            java.lang.Object r0 = androidx.work.impl.r.m
            monitor-enter(r0)
            monitor-enter(r0)     // Catch: java.lang.Throwable -> L3c
            androidx.work.impl.r r1 = androidx.work.impl.r.k     // Catch: java.lang.Throwable -> La
            if (r1 == 0) goto Lc
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La
            goto Lf
        La:
            r4 = move-exception
            goto L48
        Lc:
            androidx.work.impl.r r1 = androidx.work.impl.r.l     // Catch: java.lang.Throwable -> La
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La
        Lf:
            if (r1 != 0) goto L46
            android.content.Context r4 = r4.getApplicationContext()     // Catch: java.lang.Throwable -> L3c
            boolean r1 = r4 instanceof androidx.work.InterfaceC1421b     // Catch: java.lang.Throwable -> L3c
            if (r1 == 0) goto L3e
            r1 = r4
            androidx.work.b r1 = (androidx.work.InterfaceC1421b) r1     // Catch: java.lang.Throwable -> L3c
            com.quizlet.quizletandroid.QuizletApplication r1 = (com.quizlet.quizletandroid.QuizletApplication) r1     // Catch: java.lang.Throwable -> L3c
            r1.getClass()     // Catch: java.lang.Throwable -> L3c
            androidx.work.G r2 = new androidx.work.G     // Catch: java.lang.Throwable -> L3c
            r2.<init>()     // Catch: java.lang.Throwable -> L3c
            androidx.hilt.work.a r1 = r1.g     // Catch: java.lang.Throwable -> L3c
            java.lang.String r3 = "workerFactory"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r3)     // Catch: java.lang.Throwable -> L3c
            r2.a = r1     // Catch: java.lang.Throwable -> L3c
            androidx.work.c r1 = new androidx.work.c     // Catch: java.lang.Throwable -> L3c
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L3c
            i(r4, r1)     // Catch: java.lang.Throwable -> L3c
            androidx.work.impl.r r1 = h(r4)     // Catch: java.lang.Throwable -> L3c
            goto L46
        L3c:
            r4 = move-exception
            goto L4a
        L3e:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L3c
            java.lang.String r1 = "WorkManager is not initialized properly.  You have explicitly disabled WorkManagerInitializer in your manifest, have not manually called WorkManager#initialize at this point, and your Application does not implement Configuration.Provider."
            r4.<init>(r1)     // Catch: java.lang.Throwable -> L3c
            throw r4     // Catch: java.lang.Throwable -> L3c
        L46:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L3c
            return r1
        L48:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La
            throw r4     // Catch: java.lang.Throwable -> L3c
        L4a:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L3c
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.r.h(android.content.Context):androidx.work.impl.r");
    }

    public static void i(Context context, C1422c c1422c) {
        synchronized (m) {
            try {
                r rVar = k;
                if (rVar != null && l != null) {
                    throw new IllegalStateException("WorkManager is already initialized.  Did you try to initialize it manually without disabling WorkManagerInitializer? See WorkManager#initialize(Context, Configuration) or the class level Javadoc for more information.");
                }
                if (rVar == null) {
                    Context applicationContext = context.getApplicationContext();
                    if (l == null) {
                        l = t.c(applicationContext, c1422c);
                    }
                    k = l;
                }
            } finally {
            }
        }
    }

    public final void j() {
        synchronized (m) {
            try {
                this.h = true;
                BroadcastReceiver.PendingResult pendingResult = this.i;
                if (pendingResult != null) {
                    pendingResult.finish();
                    this.i = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void k() {
        androidx.work.B b = this.b.m;
        C1247h block = new C1247h(this, 6);
        Intrinsics.checkNotNullParameter(b, "<this>");
        Intrinsics.checkNotNullParameter("ReschedulingWork", "label");
        Intrinsics.checkNotNullParameter(block, "block");
        b.getClass();
        boolean zD = AbstractC3359k2.d();
        if (zD) {
            try {
                Intrinsics.checkNotNullParameter("ReschedulingWork", "label");
                Trace.beginSection(AbstractC3359k2.f("ReschedulingWork"));
            } finally {
                if (zD) {
                    Trace.endSection();
                }
            }
        }
        block.invoke();
    }
}
