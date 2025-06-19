package com.braze.managers;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import androidx.lifecycle.C1247h;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.SessionStateChangedEvent;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.IntentUtils;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class r {
    public static final String m = BrazeLogger.getBrazeLogTag((Class<?>) r.class);
    public static final long n;
    public static final long o;
    public final Context a;
    public final com.braze.storage.s b;
    public final com.braze.events.d c;
    public final com.braze.events.e d;
    public final AlarmManager e;
    public final int f;
    public final boolean g;
    public final ReentrantLock h;
    public final String i;
    public final C1503p j;
    public InterfaceC5025j0 k;
    public com.braze.models.l l;

    static {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        n = timeUnit.toMillis(10L);
        o = timeUnit.toMillis(10L);
    }

    public r(Context applicationContext, com.braze.storage.s sessionStorageManager, com.braze.events.d internalEventPublisher, com.braze.events.e externalEventPublisher, AlarmManager alarmManager, int i, boolean z) {
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        Intrinsics.checkNotNullParameter(sessionStorageManager, "sessionStorageManager");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(alarmManager, "alarmManager");
        this.a = applicationContext;
        this.b = sessionStorageManager;
        this.c = internalEventPublisher;
        this.d = externalEventPublisher;
        this.e = alarmManager;
        this.f = i;
        this.g = z;
        this.h = new ReentrantLock();
        this.k = kotlinx.coroutines.E.d();
        C1503p c1503p = new C1503p(this);
        this.j = c1503p;
        String str = applicationContext.getPackageName() + ".intent.BRAZE_SESSION_SHOULD_SEAL";
        this.i = str;
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                applicationContext.registerReceiver(c1503p, new IntentFilter(str), 2);
            } else {
                applicationContext.registerReceiver(c1503p, new IntentFilter(str));
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C1247h(this, 21), 4, (Object) null);
            this.j = null;
        }
    }

    public static final String a(r rVar) {
        return "Failed to register dynamic receiver for " + rVar.i;
    }

    public static final String b(com.braze.models.l lVar) {
        return "New session created with ID: " + lVar.a;
    }

    public static final String c(com.braze.models.l lVar) {
        return "Checking if this session needs to be sealed: " + lVar.a;
    }

    public static final String d(com.braze.models.l lVar) {
        return "Session [" + lVar.a + "] being sealed because its end time is over the grace period. Session: " + lVar;
    }

    public static final String e(com.braze.models.l lVar) {
        return "Closed session with id " + lVar.a;
    }

    public static final String j() {
        return "Getting the stored open session";
    }

    public static final String m() {
        return "Failed to unregister session seal receiver.";
    }

    public final boolean f() throws Throwable {
        ReentrantLock reentrantLock = this.h;
        reentrantLock.lock();
        try {
            i();
            com.braze.models.l lVar = this.l;
            boolean z = true;
            if (lVar == null || lVar.d) {
                h();
                if (lVar != null && lVar.d) {
                    try {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new O(lVar, 4), 7, (Object) null);
                        this.b.a(lVar.a.b);
                    } catch (Throwable th) {
                        th = th;
                        reentrantLock.unlock();
                        throw th;
                    }
                }
                reentrantLock.unlock();
                return z;
            }
            if (lVar.c != null) {
                lVar.c = null;
            } else {
                z = false;
            }
            reentrantLock.unlock();
            return z;
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public final com.braze.models.o g() {
        ReentrantLock reentrantLock = this.h;
        reentrantLock.lock();
        try {
            i();
            com.braze.models.l lVar = this.l;
            return lVar != null ? lVar.a : null;
        } finally {
            reentrantLock.unlock();
        }
    }

    public final void h() {
        com.braze.models.l lVar = new com.braze.models.l();
        this.l = lVar;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new O(lVar, 0), 6, (Object) null);
        this.c.b(new com.braze.events.internal.y(lVar), com.braze.events.internal.y.class);
        ((com.braze.events.d) this.d).b(new SessionStateChangedEvent(lVar.a.b, SessionStateChangedEvent.ChangeType.SESSION_STARTED), SessionStateChangedEvent.class);
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x009d A[Catch: all -> 0x0034, TryCatch #0 {all -> 0x0034, blocks: (B:3:0x0007, B:5:0x000c, B:7:0x0024, B:11:0x0038, B:12:0x003a, B:14:0x003e, B:16:0x0052, B:18:0x0056, B:20:0x006d, B:25:0x0085, B:27:0x009d, B:29:0x00a1, B:23:0x007b, B:30:0x00aa), top: B:35:0x0007 }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i() {
        /*
            r16 = this;
            r1 = r16
            java.util.concurrent.locks.ReentrantLock r8 = r1.h
            r8.lock()
            com.braze.models.l r0 = r1.l     // Catch: java.lang.Throwable -> L34
            r9 = 0
            if (r0 != 0) goto L3a
            com.braze.support.BrazeLogger r0 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Throwable -> L34
            com.braze.managers.P r5 = new com.braze.managers.P     // Catch: java.lang.Throwable -> L34
            r2 = 0
            r5.<init>(r2)     // Catch: java.lang.Throwable -> L34
            r3 = 0
            r4 = 0
            r6 = 7
            r7 = 0
            r2 = 0
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L34
            com.braze.storage.s r0 = r1.b     // Catch: java.lang.Throwable -> L34
            com.braze.models.n r0 = r0.c()     // Catch: java.lang.Throwable -> L34
            if (r0 == 0) goto L37
            com.braze.models.l r2 = new com.braze.models.l     // Catch: java.lang.Throwable -> L34
            com.braze.models.o r3 = r0.a     // Catch: java.lang.Throwable -> L34
            double r4 = r0.b     // Catch: java.lang.Throwable -> L34
            java.lang.Double r6 = r0.d()     // Catch: java.lang.Throwable -> L34
            boolean r7 = r0.d     // Catch: java.lang.Throwable -> L34
            r2.<init>(r3, r4, r6, r7)     // Catch: java.lang.Throwable -> L34
            goto L38
        L34:
            r0 = move-exception
            goto Lb0
        L37:
            r2 = r9
        L38:
            r1.l = r2     // Catch: java.lang.Throwable -> L34
        L3a:
            com.braze.models.l r10 = r1.l     // Catch: java.lang.Throwable -> L34
            if (r10 == 0) goto Lac
            com.braze.support.BrazeLogger r0 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Throwable -> L34
            com.braze.managers.O r5 = new com.braze.managers.O     // Catch: java.lang.Throwable -> L34
            r2 = 1
            r5.<init>(r10, r2)     // Catch: java.lang.Throwable -> L34
            r3 = 0
            r4 = 0
            r6 = 7
            r7 = 0
            r2 = 0
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L34
            java.lang.Double r2 = r10.c     // Catch: java.lang.Throwable -> L34
            if (r2 == 0) goto Laa
            boolean r3 = r10.d     // Catch: java.lang.Throwable -> L34
            if (r3 != 0) goto Laa
            double r3 = r10.b     // Catch: java.lang.Throwable -> L34
            double r5 = r2.doubleValue()     // Catch: java.lang.Throwable -> L34
            int r2 = r1.f     // Catch: java.lang.Throwable -> L34
            boolean r7 = r1.g     // Catch: java.lang.Throwable -> L34
            long r11 = com.braze.support.DateTimeUtils.nowInMilliseconds()     // Catch: java.lang.Throwable -> L34
            java.util.concurrent.TimeUnit r13 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L34
            long r14 = (long) r2     // Catch: java.lang.Throwable -> L34
            long r14 = r13.toMillis(r14)     // Catch: java.lang.Throwable -> L34
            if (r7 == 0) goto L7b
            long r2 = (long) r3     // Catch: java.lang.Throwable -> L34
            long r2 = r13.toMillis(r2)     // Catch: java.lang.Throwable -> L34
            long r2 = r2 + r14
            long r4 = com.braze.managers.r.o     // Catch: java.lang.Throwable -> L34
            long r2 = r2 + r4
            int r2 = (r2 > r11 ? 1 : (r2 == r11 ? 0 : -1))
            if (r2 > 0) goto Laa
            goto L85
        L7b:
            long r2 = (long) r5     // Catch: java.lang.Throwable -> L34
            long r2 = r13.toMillis(r2)     // Catch: java.lang.Throwable -> L34
            long r2 = r2 + r14
            int r2 = (r2 > r11 ? 1 : (r2 == r11 ? 0 : -1))
            if (r2 > 0) goto Laa
        L85:
            com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.I     // Catch: java.lang.Throwable -> L34
            com.braze.managers.O r5 = new com.braze.managers.O     // Catch: java.lang.Throwable -> L34
            r3 = 2
            r5.<init>(r10, r3)     // Catch: java.lang.Throwable -> L34
            r3 = 0
            r4 = 0
            r6 = 6
            r7 = 0
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L34
            r1.k()     // Catch: java.lang.Throwable -> L34
            com.braze.storage.s r0 = r1.b     // Catch: java.lang.Throwable -> L34
            com.braze.models.l r2 = r1.l     // Catch: java.lang.Throwable -> L34
            if (r2 == 0) goto La0
            com.braze.models.o r2 = r2.a     // Catch: java.lang.Throwable -> L34
            goto La1
        La0:
            r2 = r9
        La1:
            java.lang.String r2 = java.lang.String.valueOf(r2)     // Catch: java.lang.Throwable -> L34
            r0.a(r2)     // Catch: java.lang.Throwable -> L34
            r1.l = r9     // Catch: java.lang.Throwable -> L34
        Laa:
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L34
        Lac:
            r8.unlock()
            return
        Lb0:
            r8.unlock()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.managers.r.i():void");
    }

    public final void k() {
        com.braze.models.l lVar = this.l;
        if (lVar != null) {
            ReentrantLock reentrantLock = this.h;
            reentrantLock.lock();
            try {
                lVar.d = true;
                lVar.c = Double.valueOf(DateTimeUtils.nowInSecondsPrecise());
                this.b.a(lVar);
                this.c.b(new com.braze.events.internal.z(lVar), com.braze.events.internal.z.class);
                ((com.braze.events.d) this.d).b(new SessionStateChangedEvent(lVar.a.b, SessionStateChangedEvent.ChangeType.SESSION_ENDED), SessionStateChangedEvent.class);
                Unit unit = Unit.a;
            } finally {
                reentrantLock.unlock();
            }
        }
    }

    public final void l() {
        try {
            C1503p c1503p = this.j;
            if (c1503p != null) {
                this.a.unregisterReceiver(c1503p);
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new K(29), 4, (Object) null);
        }
    }

    public final void n() {
        ReentrantLock reentrantLock = this.h;
        reentrantLock.lock();
        try {
            f();
            com.braze.models.l lVar = this.l;
            if (lVar != null) {
                lVar.c = Double.valueOf(DateTimeUtils.nowInSecondsPrecise());
                this.b.a(lVar);
                this.k.j(null);
                this.k = kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new C1504q(this, null), 3);
                d();
                this.c.b(com.braze.events.internal.b0.a, com.braze.events.internal.b0.class);
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new O(lVar, 3), 7, (Object) null);
                Unit unit = Unit.a;
            }
        } finally {
            reentrantLock.unlock();
        }
    }

    public static final String a(com.braze.models.l lVar) {
        return "Clearing completely dispatched sealed session " + lVar.a;
    }

    public static final String b() {
        return "Cancelling session seal alarm";
    }

    public static final String c() {
        return "Failed to cancel session seal alarm";
    }

    public static final String e() {
        return "Failed to create session seal alarm";
    }

    public final void d() {
        com.braze.models.l mutableSession = this.l;
        if (mutableSession != null) {
            int i = this.f;
            boolean z = this.g;
            Intrinsics.checkNotNullParameter(mutableSession, "mutableSession");
            TimeUnit timeUnit = TimeUnit.SECONDS;
            long millis = timeUnit.toMillis(i);
            if (z) {
                millis = Math.max(o, (timeUnit.toMillis((long) mutableSession.b) + millis) - DateTimeUtils.nowInMilliseconds());
            }
            long j = millis;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(7, j), 7, (Object) null);
            try {
                Intent intent = new Intent(this.i);
                intent.putExtra("session_id", mutableSession.toString());
                this.e.set(1, DateTimeUtils.nowInMilliseconds() + j, PendingIntent.getBroadcast(this.a, 0, intent, IntentUtils.getImmutablePendingIntentFlags() | 1073741824));
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(3), 4, (Object) null);
            }
        }
    }

    public static final String a(long j) {
        return androidx.compose.animation.d0.o(j, "Creating a session seal alarm with a delay of ", " ms");
    }

    public final void a() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(1), 7, (Object) null);
        try {
            Intent intent = new Intent(this.i);
            intent.putExtra("session_id", String.valueOf(this.l));
            this.e.cancel(PendingIntent.getBroadcast(this.a, 0, intent, IntentUtils.getImmutablePendingIntentFlags() | 1073741824));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(2), 4, (Object) null);
        }
    }
}
