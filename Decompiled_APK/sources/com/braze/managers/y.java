package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.lifecycle.C1247h;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1484j;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IEventSubscriber;
import com.braze.support.BrazeLogger;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class y {
    public static final long f = TimeUnit.SECONDS.toMillis(5);
    public final com.braze.storage.e0 a;
    public final com.braze.events.d b;
    public final SharedPreferences c;
    public final com.braze.communication.dust.h d;
    public InterfaceC5025j0 e;

    public y(com.braze.storage.e0 serverConfigStorageProvider, com.braze.events.d internalPublisher, Context context, String str, String str2) {
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = serverConfigStorageProvider;
        this.b = internalPublisher;
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.managers.dust.metadata", str, str2);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.c = sharedPreferencesG;
        this.d = new com.braze.communication.dust.h();
        final int i = 0;
        internalPublisher.c(com.braze.events.internal.a0.class, new IEventSubscriber(this) { // from class: com.braze.managers.S
            public final /* synthetic */ y b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) throws Throwable {
                switch (i) {
                    case 0:
                        y.a(this.b, (com.braze.events.internal.a0) obj);
                        break;
                    case 1:
                        y.a(this.b, (com.braze.events.internal.b0) obj);
                        break;
                    case 2:
                        y.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                    default:
                        y.a(this.b, (com.braze.events.internal.h) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        internalPublisher.c(com.braze.events.internal.b0.class, new IEventSubscriber(this) { // from class: com.braze.managers.S
            public final /* synthetic */ y b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) throws Throwable {
                switch (i2) {
                    case 0:
                        y.a(this.b, (com.braze.events.internal.a0) obj);
                        break;
                    case 1:
                        y.a(this.b, (com.braze.events.internal.b0) obj);
                        break;
                    case 2:
                        y.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                    default:
                        y.a(this.b, (com.braze.events.internal.h) obj);
                        break;
                }
            }
        });
        final int i3 = 2;
        internalPublisher.c(com.braze.events.internal.o.class, new IEventSubscriber(this) { // from class: com.braze.managers.S
            public final /* synthetic */ y b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) throws Throwable {
                switch (i3) {
                    case 0:
                        y.a(this.b, (com.braze.events.internal.a0) obj);
                        break;
                    case 1:
                        y.a(this.b, (com.braze.events.internal.b0) obj);
                        break;
                    case 2:
                        y.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                    default:
                        y.a(this.b, (com.braze.events.internal.h) obj);
                        break;
                }
            }
        });
        final int i4 = 3;
        internalPublisher.c(com.braze.events.internal.h.class, new IEventSubscriber(this) { // from class: com.braze.managers.S
            public final /* synthetic */ y b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) throws Throwable {
                switch (i4) {
                    case 0:
                        y.a(this.b, (com.braze.events.internal.a0) obj);
                        break;
                    case 1:
                        y.a(this.b, (com.braze.events.internal.b0) obj);
                        break;
                    case 2:
                        y.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                    default:
                        y.a(this.b, (com.braze.events.internal.h) obj);
                        break;
                }
            }
        });
    }

    public static final void a(y yVar, com.braze.events.internal.a0 it2) throws Throwable {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) yVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(21), 7, (Object) null);
        InterfaceC5025j0 interfaceC5025j0 = yVar.e;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        yVar.a(true);
    }

    public static final String b(String str) {
        return AbstractC1484j.a("setting mite value to ", str);
    }

    public static final String c() {
        return "Cancelling ending of DUST subscription on delay and resuming stream";
    }

    public static final String d() {
        return "Ending DUST subscription on delay";
    }

    public static final String e() {
        return "Received MITE value. Starting/resuming a new subscription";
    }

    public static final String b() {
        return "Ending DUST subscription";
    }

    public static final String b(com.braze.models.dust.e eVar) {
        return "Ingesting DUST message\n" + eVar;
    }

    public static final void a(y yVar, com.braze.events.internal.b0 it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) yVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(22), 7, (Object) null);
        yVar.e = BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, Long.valueOf(f), null, new v(yVar, null), 2, null);
    }

    public static final void a(y yVar, com.braze.events.internal.o it2) throws Throwable {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) yVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new T(it2, 0), 7, (Object) null);
        com.braze.enums.f fVar = it2.b;
        com.braze.enums.f fVar2 = com.braze.enums.f.a;
        if (fVar == fVar2) {
            yVar.a();
        } else if (it2.a == fVar2) {
            yVar.a(true);
        }
    }

    public static final String a(com.braze.events.internal.o oVar) {
        return "Got network change event: " + oVar;
    }

    public static final void a(y yVar, com.braze.events.internal.h it2) throws Throwable {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) yVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(23), 7, (Object) null);
        String string = yVar.c.getString("mite", null);
        yVar.a(it2.a);
        yVar.a(Intrinsics.b(string, it2.a));
    }

    public final void a(String str) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(str, 13), 7, (Object) null);
        this.c.edit().putString("mite", str).apply();
    }

    public static final String a(String str, y yVar) {
        StringBuilder sbY = android.support.v4.media.session.a.y("Cannot start a dust subscription with mite ", str, " and enabled ");
        sbY.append(yVar.a.E());
        return sbY.toString();
    }

    public static final String a(boolean z, String str, String str2) {
        return "Starting (resume = " + z + ") DUST subscription for mite: " + str + " to url: " + str2;
    }

    public final void a() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(24), 7, (Object) null);
        this.d.b();
    }

    public final void a(com.braze.models.dust.e eVar) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(eVar, 24), 7, (Object) null);
        com.braze.models.dust.d dVarA = eVar.a();
        if (w.a[dVarA.ordinal()] == 1) {
            this.b.b(new com.braze.events.internal.e(), com.braze.events.internal.e.class);
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1247h(dVarA, 25), 6, (Object) null);
        }
    }

    public static final String a(com.braze.models.dust.d dVar) {
        return "Lacked logic to ingest message! Type: " + dVar;
    }

    public final void a(boolean z) throws Throwable {
        String string = this.c.getString("mite", null);
        if (string != null && this.a.E()) {
            String strConcat = "https://dust.k8s.test-001.d-usw-2.braze.com/sse?mite=".concat(string);
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.r(z, string, strConcat, 1), 7, (Object) null);
            this.d.a(strConcat, new x(this), z);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(10, string, this), 7, (Object) null);
    }
}
