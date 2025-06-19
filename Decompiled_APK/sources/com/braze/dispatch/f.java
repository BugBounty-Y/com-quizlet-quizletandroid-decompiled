package com.braze.dispatch;

import android.content.Context;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import androidx.compose.animation.d0;
import com.braze.Braze;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IEventSubscriber;
import com.braze.events.internal.a0;
import com.braze.events.internal.b0;
import com.braze.events.internal.o;
import com.braze.support.BrazeLogger;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class f {
    public static final String m = BrazeLogger.getBrazeLogTag((Class<?>) f.class);
    public final Context a;
    public final com.braze.events.d b;
    public final a c;
    public final d d;
    public final b e;
    public com.braze.enums.g f;
    public long g;
    public volatile boolean h;
    public final ConnectivityManager i;
    public com.braze.enums.f j;
    public InterfaceC5025j0 k;
    public boolean l;

    public f(Context context, com.braze.events.d internalEventPublisher, a dataSyncConfigurationProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(dataSyncConfigurationProvider, "dataSyncConfigurationProvider");
        this.a = context;
        this.b = internalEventPublisher;
        this.c = dataSyncConfigurationProvider;
        this.f = com.braze.enums.g.b;
        this.g = -1L;
        Object systemService = context.getSystemService("connectivity");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.net.ConnectivityManager");
        this.i = (ConnectivityManager) systemService;
        this.j = com.braze.enums.f.c;
        if (Build.VERSION.SDK_INT >= 30) {
            this.e = new b(this);
        } else {
            this.d = new d(this);
        }
        a(internalEventPublisher);
    }

    public static final String d() {
        return "The data sync policy is already running. Ignoring request.";
    }

    public static final String e() {
        return "Data sync started";
    }

    public static final String g() {
        return "The data sync policy is not running. Ignoring request.";
    }

    public static final String h() {
        return "Data sync stopped";
    }

    public static final String j() {
        return "Failed to unregister Connectivity callback";
    }

    public final InterfaceC5025j0 a(long j) {
        if (this.g >= 1000) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new k(j, this, 0), 6, (Object) null);
            return E.A(BrazeCoroutineScope.INSTANCE, null, null, new e(this, j, null), 3);
        }
        Braze.Companion.getInstance(this.a).requestImmediateDataFlush();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(this, 1), 7, (Object) null);
        return null;
    }

    public final void b(long j) {
        InterfaceC5025j0 interfaceC5025j0 = this.k;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        this.k = null;
        if (this.g >= 1000) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(0, j), 7, (Object) null);
            this.k = a(j);
        }
    }

    public final synchronized void c() {
        if (this.h) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(10), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(11), 7, (Object) null);
        if (Build.VERSION.SDK_INT >= 30) {
            ConnectivityManager connectivityManager = this.i;
            b bVar = this.e;
            if (bVar == null) {
                Intrinsics.m("connectivityNetworkCallback");
                throw null;
            }
            connectivityManager.registerDefaultNetworkCallback(bVar);
            a(this.i.getNetworkCapabilities(this.i.getActiveNetwork()));
        } else {
            this.a.registerReceiver(this.d, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
        }
        b(this.g);
        this.h = true;
    }

    public final synchronized void f() {
        if (!this.h) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(8), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(9), 7, (Object) null);
        InterfaceC5025j0 interfaceC5025j0 = this.k;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        this.k = null;
        i();
        this.h = false;
    }

    public final void i() {
        try {
            if (Build.VERSION.SDK_INT < 30) {
                this.a.unregisterReceiver(this.d);
                return;
            }
            ConnectivityManager connectivityManager = this.i;
            b bVar = this.e;
            if (bVar != null) {
                connectivityManager.unregisterNetworkCallback(bVar);
            } else {
                Intrinsics.m("connectivityNetworkCallback");
                throw null;
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.configuration.h(7), 4, (Object) null);
        }
    }

    public static final String d(f fVar) {
        return android.support.v4.media.session.a.g(fVar.g, "), moving to minimum of 1000 ms", new StringBuilder("Flush interval was too low ("));
    }

    public static final String a(long j, f fVar) {
        return android.support.v4.media.session.a.g(fVar.g, " ms", d0.t(j, "Kicking off the Sync Job. initialDelaysMs: ", ": currentIntervalMs "));
    }

    public final void b() {
        long j;
        int intValue;
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new i(this, 0), 6, (Object) null);
        long j2 = this.g;
        if (this.f != com.braze.enums.g.b && !this.l) {
            int iOrdinal = this.j.ordinal();
            if (iOrdinal != 0) {
                if (iOrdinal == 1) {
                    a aVar = this.c;
                    aVar.getClass();
                    com.braze.configuration.b bVar = com.braze.configuration.b.b;
                    intValue = aVar.getIntValue("com_braze_data_flush_interval_bad_network", 60);
                } else if (iOrdinal == 2) {
                    a aVar2 = this.c;
                    aVar2.getClass();
                    com.braze.configuration.b bVar2 = com.braze.configuration.b.b;
                    intValue = aVar2.getIntValue("com_braze_data_flush_interval_good_network", 30);
                } else if (iOrdinal == 3) {
                    a aVar3 = this.c;
                    aVar3.getClass();
                    com.braze.configuration.b bVar3 = com.braze.configuration.b.b;
                    intValue = aVar3.getIntValue("com_braze_data_flush_interval_great_network", 10);
                } else {
                    throw new NoWhenBranchMatchedException();
                }
                j = intValue * 1000;
            } else {
                j = -1;
            }
            this.g = j;
            if (j != -1 && j < 1000) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new i(this, 2), 6, (Object) null);
                this.g = 1000L;
            }
        } else {
            this.g = -1L;
        }
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new i(this, 3), 6, (Object) null);
        if (j2 != this.g) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(j2, this, 1), 7, (Object) null);
            b(this.g);
        }
    }

    public static final String c(long j) {
        return d0.o(j, "Posting new sync runnable with delay ", " ms");
    }

    public static final String a(f fVar) {
        return android.support.v4.media.session.a.g(fVar.g, " ms. Not scheduling a proceeding data flush.", new StringBuilder("Data flush interval is "));
    }

    public static final String c(f fVar) {
        return "recalculateDispatchState called with session state: " + fVar.f + " lastNetworkLevel: " + fVar.j;
    }

    public final void a(com.braze.events.d dVar, Exception exc) {
        try {
            dVar.b(exc, Throwable.class);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.configuration.h(6), 4, (Object) null);
        }
    }

    public static final String a() {
        return "Failed to log throwable.";
    }

    public final void a(NetworkCapabilities networkCapabilities) {
        com.braze.enums.f fVar = this.j;
        com.braze.enums.f fVarA = com.braze.support.c.a(networkCapabilities);
        this.j = fVarA;
        if (fVar != fVarA) {
            this.b.b(new o(fVar, fVarA), o.class);
        }
        b();
    }

    public final void a(com.braze.events.d eventManager) {
        Intrinsics.checkNotNullParameter(eventManager, "eventManager");
        final int i = 0;
        eventManager.c(a0.class, new IEventSubscriber(this) { // from class: com.braze.dispatch.l
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        f.a(this.b, (a0) obj);
                        break;
                    default:
                        f.a(this.b, (b0) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        eventManager.c(b0.class, new IEventSubscriber(this) { // from class: com.braze.dispatch.l
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        f.a(this.b, (a0) obj);
                        break;
                    default:
                        f.a(this.b, (b0) obj);
                        break;
                }
            }
        });
    }

    public static final void a(f fVar, a0 it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        fVar.f = com.braze.enums.g.a;
        fVar.b();
    }

    public static final String b(f fVar) {
        return "currentIntervalMs: " + fVar.g;
    }

    public static final void a(f fVar, b0 it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        fVar.f = com.braze.enums.g.b;
        fVar.b();
    }

    public static final String b(long j, f fVar) {
        StringBuilder sbT = d0.t(j, "Data flush interval has changed from ", " ms to ");
        sbT.append(fVar.g);
        sbT.append(" ms after connectivity state change to: ");
        sbT.append(fVar.j);
        sbT.append(" and session state: ");
        sbT.append(fVar.f);
        return sbT.toString();
    }
}
