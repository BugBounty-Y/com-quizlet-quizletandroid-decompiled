package com.quizlet.shared.cache;

import com.google.android.gms.measurement.internal.J;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class s implements a {
    public final J a;
    public final kotlinx.coroutines.scheduling.e b;
    public final com.quizlet.remote.model.set.d c;

    public s(J kache, kotlinx.coroutines.scheduling.e dispatcher, com.quizlet.remote.model.set.d json, com.quizlet.quizletandroid.ui.folder.logging.a writeToFileUseCase, com.quizlet.quizletandroid.ui.common.images.capture.b readFileContentsUseCase) {
        Intrinsics.checkNotNullParameter(kache, "kache");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(writeToFileUseCase, "writeToFileUseCase");
        Intrinsics.checkNotNullParameter(readFileContentsUseCase, "readFileContentsUseCase");
        this.a = kache;
        this.b = dispatcher;
        this.c = json;
    }

    @Override // com.quizlet.shared.cache.a
    public final Object a(kotlin.coroutines.jvm.internal.c cVar) {
        return E.J(this.b, new q(this, null), cVar);
    }

    @Override // com.quizlet.shared.cache.a
    public final Object b(Object obj, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        Object objJ = E.J(this.b, new r(this, (serialization.e) obj, null), cVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }

    @Override // com.quizlet.shared.cache.a
    public final Object c(kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        Object objJ = E.J(this.b, new p(this, null), cVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }
}
