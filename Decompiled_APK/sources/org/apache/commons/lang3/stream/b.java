package org.apache.commons.lang3.stream;

import java.util.Objects;
import java.util.StringJoiner;
import java.util.function.BiConsumer;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements BiConsumer {
    @Override // java.util.function.BiConsumer
    public final void accept(Object obj, Object obj2) {
        ((StringJoiner) obj).add(Objects.toString(obj2, ""));
    }
}
