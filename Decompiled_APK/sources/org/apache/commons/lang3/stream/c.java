package org.apache.commons.lang3.stream;

import java.util.StringJoiner;
import java.util.function.BinaryOperator;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements BinaryOperator {
    @Override // java.util.function.BiFunction
    public final Object apply(Object obj, Object obj2) {
        return ((StringJoiner) obj).merge((StringJoiner) obj2);
    }
}
