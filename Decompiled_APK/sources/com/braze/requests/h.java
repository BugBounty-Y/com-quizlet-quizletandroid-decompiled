package com.braze.requests;

import com.braze.managers.C1500m;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements p {
    public final com.braze.events.e a;
    public final C1500m b;

    public h(com.braze.events.e internalEventPublisher, C1500m brazeManager) {
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.a = internalEventPublisher;
        this.b = brazeManager;
        new ArrayList();
    }

    @Override // com.braze.requests.p
    public final void a(com.braze.requests.framework.h requestInfo, com.braze.requests.framework.c requestDispatchCallback, boolean z) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        Intrinsics.checkNotNullParameter(requestDispatchCallback, "requestDispatchCallback");
        n nVar = requestInfo.a;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.requests.framework.o(nVar, 3), 7, (Object) null);
        com.braze.models.response.g gVar = new com.braze.models.response.g(nVar, new com.braze.communication.d(201, V.c(), 4), this.b);
        com.braze.events.e eVar = this.a;
        nVar.a(eVar, eVar, gVar);
        nVar.a(this.a);
        requestDispatchCallback.a(gVar);
        ((com.braze.events.d) this.a).b(new com.braze.events.internal.g(nVar), com.braze.events.internal.g.class);
    }

    public static final String a(n nVar) {
        return "Short circuiting execution of network request (" + nVar.hashCode() + ") and immediately marking it as succeeded.";
    }
}
