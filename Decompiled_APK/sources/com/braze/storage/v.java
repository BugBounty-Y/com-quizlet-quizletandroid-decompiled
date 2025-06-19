package com.braze.storage;

import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1484j;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.support.BrazeLogger;
import java.util.Collection;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.M;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class v {
    public final f0 a;
    public final com.braze.events.d b;
    public boolean c;

    public v(f0 storage, com.braze.events.d eventPublisher) {
        Intrinsics.checkNotNullParameter(storage, "storage");
        Intrinsics.checkNotNullParameter(eventPublisher, "eventPublisher");
        this.a = storage;
        this.b = eventPublisher;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Storage provider is closed. Failed to ", str);
    }

    public static final String b() {
        return "Failed to get all events from storage.";
    }

    public static final String d() {
        return "Failed to log storage exception";
    }

    public final Collection c() {
        if (this.c) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new F(0), 6, (Object) null);
            return M.a;
        }
        try {
            return this.a.b();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new F(1), 4, (Object) null);
            a(e);
            return M.a;
        }
    }

    public static final String a() {
        return "Storage provider is closed. Not getting all events.";
    }

    public final void a(com.braze.models.i event) {
        Intrinsics.checkNotNullParameter(event, "event");
        a("add event " + event, new C1277j(21, this, event));
    }

    public static final Unit a(v vVar, com.braze.models.i iVar) {
        vVar.a.a(iVar);
        return Unit.a;
    }

    public final void a(Set events) {
        Intrinsics.checkNotNullParameter(events, "events");
        a("delete events " + events, new C1277j(22, this, events));
    }

    public static final Unit a(v vVar, Set set) {
        vVar.a.a(set);
        return Unit.a;
    }

    public final void a(Exception exc) {
        try {
            this.b.b(new com.braze.exceptions.b("A storage exception has occurred!", exc), com.braze.exceptions.b.class);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new F(2), 4, (Object) null);
        }
    }

    public final void a(String str, Function0 function0) {
        if (this.c) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new D(str, 13), 6, (Object) null);
        } else {
            kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new u(function0, this, str, null), 3);
        }
    }
}
