package io.ktor.client.engine;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements CoroutineContext.Element {
    public static final com.quizlet.quizletandroid.ui.joincontenttofolder.j b = new com.quizlet.quizletandroid.ui.joincontenttofolder.j(5);
    public final CoroutineContext a;

    public j(CoroutineContext callContext) {
        Intrinsics.checkNotNullParameter(callContext, "callContext");
        this.a = callContext;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext.Element
    public final kotlin.coroutines.l getKey() {
        return b;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }
}
