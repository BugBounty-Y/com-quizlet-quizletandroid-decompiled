package androidx.compose.runtime.external.kotlinx.collections.immutable;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.g;
import java.util.Collection;
import java.util.List;

/* loaded from: classes.dex */
public interface c extends List, Collection, kotlin.jvm.internal.markers.a {
    c Y(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.b bVar);

    @Override // java.util.List
    c add(int i, Object obj);

    @Override // java.util.List, java.util.Collection
    c add(Object obj);

    @Override // java.util.List, java.util.Collection
    c addAll(Collection collection);

    g builder();

    @Override // java.util.List
    c set(int i, Object obj);

    c y(int i);
}
