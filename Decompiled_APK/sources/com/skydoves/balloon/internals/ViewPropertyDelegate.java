package com.skydoves.balloon.internals;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.n;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ViewPropertyDelegate<T> {

    @NotNull
    private final Function0<Unit> invalidator;
    private T propertyValue;

    public ViewPropertyDelegate(T t, @NotNull Function0<Unit> invalidator) {
        Intrinsics.checkNotNullParameter(invalidator, "invalidator");
        this.invalidator = invalidator;
        this.propertyValue = t;
    }

    public T getValue(Object obj, @NotNull n property) {
        Intrinsics.checkNotNullParameter(property, "property");
        return this.propertyValue;
    }

    public void setValue(Object obj, @NotNull n property, T t) {
        Intrinsics.checkNotNullParameter(property, "property");
        if (Intrinsics.b(this.propertyValue, t)) {
            return;
        }
        this.propertyValue = t;
        this.invalidator.invoke();
    }
}
