package com.fasterxml.jackson.databind.introspect;

import java.util.Objects;
import java.util.StringJoiner;
import java.util.function.Function;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function {
    public final /* synthetic */ int b;

    @Override // java.util.function.Function
    public final Object apply(Object obj) {
        switch (this.b) {
            case 0:
                return ((AnnotatedMethod) obj).getFullName();
            case 1:
                return Objects.toString(obj, "");
            default:
                return ((StringJoiner) obj).toString();
        }
    }
}
