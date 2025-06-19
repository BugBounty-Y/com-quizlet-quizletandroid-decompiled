package androidx.compose.ui;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes.dex */
public interface r extends CoroutineContext.Element {
    float D();

    @Override // kotlin.coroutines.CoroutineContext.Element
    default kotlin.coroutines.l getKey() {
        return b.p;
    }
}
