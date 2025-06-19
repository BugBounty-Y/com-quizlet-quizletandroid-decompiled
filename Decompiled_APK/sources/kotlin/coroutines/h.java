package kotlin.coroutines;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public interface h<T> {
    CoroutineContext getContext();

    void resumeWith(Object obj);
}
