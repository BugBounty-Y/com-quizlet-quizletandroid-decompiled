package androidx.datastore;

import android.content.Context;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Context it2 = (Context) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return K.a;
    }
}
