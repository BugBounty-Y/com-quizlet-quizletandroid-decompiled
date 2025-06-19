package com.braze.managers;

import android.content.Context;
import androidx.lifecycle.C1247h;
import androidx.navigation.compose.C1277j;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IEventSubscriber;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class s0 {
    public static final n0 k = new n0();
    public final com.braze.storage.e0 a;
    public final com.braze.events.d b;
    public o0 c;
    public long d;
    public int e;
    public final ArrayList f;
    public int g;
    public final ReentrantLock h;
    public InterfaceC5025j0 i;
    public final AtomicInteger j;

    public s0(com.braze.storage.e0 serverConfigStorageProvider, com.braze.events.d internalPublisher, Context context) {
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = serverConfigStorageProvider;
        this.b = internalPublisher;
        this.c = new o0();
        this.d = DateTimeUtils.nowInSeconds();
        this.f = new ArrayList();
        this.h = new ReentrantLock();
        this.j = new AtomicInteger(0);
        if (g()) {
            c();
        }
        final int i = 0;
        internalPublisher.c(com.braze.events.internal.q.class, new IEventSubscriber(this) { // from class: com.braze.managers.Q
            public final /* synthetic */ s0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        s0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    default:
                        s0.a(this.b, (com.braze.events.internal.t) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        internalPublisher.c(com.braze.events.internal.t.class, new IEventSubscriber(this) { // from class: com.braze.managers.Q
            public final /* synthetic */ s0 b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        s0.a(this.b, (com.braze.events.internal.q) obj);
                        break;
                    default:
                        s0.a(this.b, (com.braze.events.internal.t) obj);
                        break;
                }
            }
        });
    }

    public static final void a(s0 s0Var, com.braze.events.internal.q it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (it2.a instanceof com.braze.requests.w) {
            s0Var.j.decrementAndGet();
            kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new m0(s0Var, null), 3);
        }
    }

    public static final String b() {
        return "Shutting down SDK Debugger due to being past expiration time";
    }

    public static final String d() {
        return "Initializing SDK Debugger";
    }

    public static final String e() {
        return "SDK Debugger transitioned from disabled to enabled. Initializing SDK Debugger.";
    }

    public static final String f() {
        return "SDK Debugger transitioned from enabled to disabled. Shutting down SDK Debugger.";
    }

    public static final String h() {
        return "Debugging session has expired. Disabling SDK Debugger.";
    }

    public static final String j() {
        return "Shutting down SDK Debugger";
    }

    public final void c() {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(7), 7, (Object) null);
        brazeLogger.setSdkDebuggerCallback$android_sdk_base_release(new q0(this));
        this.b.b(new com.braze.events.internal.u(), com.braze.events.internal.u.class);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x006f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean g() {
        /*
            r9 = this;
            com.braze.managers.o0 r0 = r9.c
            com.braze.storage.e0 r1 = r9.a
            boolean r1 = r1.L()
            r0.a = r1
            com.braze.managers.o0 r0 = r9.c
            boolean r1 = r0.a
            if (r1 == 0) goto L44
            com.braze.storage.e0 r1 = r9.a
            java.lang.String r1 = r1.y()
            r0.c = r1
            com.braze.managers.o0 r0 = r9.c
            com.braze.storage.e0 r1 = r9.a
            long r1 = r1.A()
            r0.d = r1
            com.braze.managers.o0 r0 = r9.c
            com.braze.storage.e0 r1 = r9.a
            long r1 = r1.B()
            r0.e = r1
            com.braze.managers.o0 r0 = r9.c
            com.braze.storage.e0 r1 = r9.a
            long r1 = r1.C()
            r0.f = r1
            com.braze.managers.o0 r0 = r9.c
            com.braze.storage.e0 r1 = r9.a
            long r1 = r1.z()
            java.lang.Long r1 = java.lang.Long.valueOf(r1)
            r0.b = r1
        L44:
            com.braze.managers.o0 r0 = r9.c
            java.lang.Long r0 = r0.b
            if (r0 == 0) goto L6f
            long r0 = r0.longValue()
            long r2 = com.braze.support.DateTimeUtils.nowInSeconds()
            int r0 = (r2 > r0 ? 1 : (r2 == r0 ? 0 : -1))
            if (r0 <= 0) goto L6f
            com.braze.support.BrazeLogger r1 = com.braze.support.BrazeLogger.INSTANCE
            com.braze.managers.P r6 = new com.braze.managers.P
            r0 = 6
            r6.<init>(r0)
            r7 = 7
            r8 = 0
            r3 = 0
            r4 = 0
            r5 = 0
            r2 = r9
            com.braze.support.BrazeLogger.brazelog$default(r1, r2, r3, r4, r5, r6, r7, r8)
            com.braze.managers.o0 r0 = new com.braze.managers.o0
            r0.<init>()
            r2.c = r0
            goto L70
        L6f:
            r2 = r9
        L70:
            com.braze.managers.o0 r0 = r2.c
            boolean r0 = r0.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.managers.s0.g():boolean");
    }

    public final void i() {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(5), 7, (Object) null);
        brazeLogger.setSdkDebuggerCallback$android_sdk_base_release(null);
        this.c = new o0();
        ReentrantLock reentrantLock = this.h;
        reentrantLock.lock();
        try {
            this.f.clear();
            this.g = 0;
            Unit unit = Unit.a;
        } finally {
            reentrantLock.unlock();
        }
    }

    public static final void a(s0 s0Var, com.braze.events.internal.t newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        o0 o0Var = s0Var.c;
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) s0Var, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(9, newConfig, o0Var), 7, (Object) null);
        if (newConfig.a.b == null) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) s0Var, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(o0Var, 22), 7, (Object) null);
            newConfig.a.b = o0Var.b;
        }
        o0 o0Var2 = newConfig.a;
        if (o0Var2.c == null) {
            o0Var2.c = o0Var.c;
        }
        s0Var.c = o0Var2;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) s0Var, priority, (Throwable) null, false, (Function0) new C1247h(newConfig, 23), 6, (Object) null);
        s0Var.a.a(newConfig.a);
        boolean z = o0Var.a;
        if (!z && s0Var.c.a) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) s0Var, priority, (Throwable) null, false, (Function0) new P(8), 6, (Object) null);
            s0Var.c();
        } else {
            if (!z || s0Var.c.a) {
                return;
            }
            BrazeLogger.brazelog$default(brazeLogger, (Object) s0Var, priority, (Throwable) null, false, (Function0) new P(9), 6, (Object) null);
            s0Var.i();
        }
    }

    public static final String a(com.braze.events.internal.t tVar, o0 o0Var) {
        return "Received SdkDebuggerConfigUpdateEvent. Updating SDK Debugger config with " + tVar.a + ".\nOld config " + o0Var;
    }

    public static final String a(o0 o0Var) {
        return "updating expiration time to " + o0Var.b;
    }

    public static final String a(com.braze.events.internal.t tVar) {
        return "Updating SDK Debugger config with " + tVar.a;
    }

    public final void a(String str) {
        com.braze.models.m mVar = new com.braze.models.m(str);
        ReentrantLock reentrantLock = this.h;
        reentrantLock.lock();
        try {
            this.f.add(mVar);
            int length = this.g + mVar.a.length();
            this.g = length;
            if (length > 1048576) {
                while (this.g > 838860) {
                    this.g -= ((com.braze.models.m) this.f.remove(0)).a.length();
                    this.e++;
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final Unit a() {
        Long l;
        o0 o0Var = this.c;
        if (o0Var.a && o0Var.c != null && (l = o0Var.b) != null && l.longValue() != 0 && this.j.get() <= 0) {
            Long l2 = this.c.b;
            if (l2 != null) {
                if (DateTimeUtils.nowInSeconds() > l2.longValue()) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(10), 7, (Object) null);
                    i();
                    return Unit.a;
                }
            }
            long jNowInSeconds = DateTimeUtils.nowInSeconds();
            long j = this.d;
            o0 o0Var2 = this.c;
            long j2 = j + o0Var2.e;
            if (jNowInSeconds <= j2 && this.g <= o0Var2.d) {
                if (this.i == null) {
                    this.i = BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, new Long(TimeUnit.SECONDS.toMillis(j2 - DateTimeUtils.nowInSeconds())), null, new p0(this, null), 2, null);
                }
            } else {
                ArrayList arrayList = new ArrayList();
                ReentrantLock reentrantLock = this.h;
                reentrantLock.lock();
                try {
                    Iterator it2 = this.f.iterator();
                    int length = 0;
                    int length2 = 0;
                    while (it2.hasNext()) {
                        com.braze.models.m mVar = (com.braze.models.m) it2.next();
                        if (this.e != 0) {
                            String str = "Removed " + this.e + " logs due to buffer overflow";
                            arrayList.add(new com.braze.models.m(str));
                            this.e = 0;
                            length2 += str.length();
                        }
                        int length3 = mVar.a.length() + length2;
                        if (length3 <= this.c.f) {
                            arrayList.add(mVar);
                            length2 = length3;
                        }
                    }
                    Iterator it3 = arrayList.iterator();
                    while (it3.hasNext()) {
                        this.f.remove((com.braze.models.m) it3.next());
                    }
                    Iterator it4 = this.f.iterator();
                    while (it4.hasNext()) {
                        length += ((com.braze.models.m) it4.next()).a.length();
                    }
                    this.g = length;
                    this.d = DateTimeUtils.nowInSeconds();
                    Unit unit = Unit.a;
                    reentrantLock.unlock();
                    InterfaceC5025j0 interfaceC5025j0 = this.i;
                    if (interfaceC5025j0 != null) {
                        interfaceC5025j0.j(null);
                    }
                    this.i = null;
                    if (!arrayList.isEmpty()) {
                        this.j.incrementAndGet();
                        this.b.b(new com.braze.events.internal.v(arrayList), com.braze.events.internal.v.class);
                    }
                } catch (Throwable th) {
                    reentrantLock.unlock();
                    throw th;
                }
            }
            return Unit.a;
        }
        return Unit.a;
    }
}
