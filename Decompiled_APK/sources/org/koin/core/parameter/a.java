package org.koin.core.parameter;

import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final ArrayList a;
    public int b;

    public a() {
        ArrayList _values = new ArrayList();
        Intrinsics.checkNotNullParameter(_values, "_values");
        this.a = _values;
    }

    public final String toString() {
        return "DefinitionParameters" + CollectionsKt.w0(this.a);
    }
}
