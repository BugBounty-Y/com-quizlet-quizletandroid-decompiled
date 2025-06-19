package com.braze.requests;

import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.managers.C1500m;
import com.braze.storage.e0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class u implements p {
    public final com.braze.communication.e a;
    public final com.braze.events.e b;
    public final com.braze.events.e c;
    public final com.braze.storage.x d;
    public final e0 e;
    public final com.braze.storage.p f;
    public final C1500m g;
    public final com.braze.requests.util.a h;

    public u(com.braze.communication.e httpConnector, com.braze.events.e internalEventPublisher, com.braze.events.e externalEventPublisher, com.braze.storage.x feedStorageProvider, e0 serverConfigStorageProvider, com.braze.storage.p contentCardsStorageProvider, C1500m brazeManager, com.braze.requests.util.a endpointMetadataProvider) {
        Intrinsics.checkNotNullParameter(httpConnector, "httpConnector");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(feedStorageProvider, "feedStorageProvider");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(contentCardsStorageProvider, "contentCardsStorageProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(endpointMetadataProvider, "endpointMetadataProvider");
        this.a = httpConnector;
        this.b = internalEventPublisher;
        this.c = externalEventPublisher;
        this.d = feedStorageProvider;
        this.e = serverConfigStorageProvider;
        this.f = contentCardsStorageProvider;
        this.g = brazeManager;
        this.h = endpointMetadataProvider;
    }

    @Override // com.braze.requests.p
    public final void a(com.braze.requests.framework.h requestInfo, com.braze.requests.framework.c requestDispatchCallback, boolean z) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        Intrinsics.checkNotNullParameter(requestDispatchCallback, "requestDispatchCallback");
        if (z) {
            new d(requestInfo, this.a, this.b, this.c, this.d, this.g, this.e, this.f, this.h, requestDispatchCallback).c();
        } else {
            E.A(BrazeCoroutineScope.INSTANCE, null, null, new t(this, requestInfo, requestDispatchCallback, null), 3);
        }
    }
}
