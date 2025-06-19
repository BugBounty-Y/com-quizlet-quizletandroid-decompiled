package com.google.firebase.sessions;

import androidx.datastore.core.InterfaceC1076h;
import androidx.paging.J0;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L {
    public final CoroutineContext a;
    public final InterfaceC1076h b;
    public final AtomicReference c;
    public final androidx.compose.material3.internal.H d;

    public L(CoroutineContext backgroundDispatcher, InterfaceC1076h dataStore) {
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.a = backgroundDispatcher;
        this.b = dataStore;
        this.c = new AtomicReference();
        this.d = new androidx.compose.material3.internal.H(1, new J0(dataStore.getData(), new H(3, 0, null)), this);
        kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(backgroundDispatcher), null, null, new F(this, null), 3);
    }
}
