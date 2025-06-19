package androidx.datastore.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c0 extends l0 {
    public final Throwable b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c0(int i, Throwable readException) {
        super(i);
        Intrinsics.checkNotNullParameter(readException, "readException");
        this.b = readException;
    }
}
