package androidx.sqlite.db.framework;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends RuntimeException {
    public final e a;
    public final Throwable b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e callbackName, Throwable cause) {
        super(cause);
        Intrinsics.checkNotNullParameter(callbackName, "callbackName");
        Intrinsics.checkNotNullParameter(cause, "cause");
        this.a = callbackName;
        this.b = cause;
    }

    @Override // java.lang.Throwable
    public final Throwable getCause() {
        return this.b;
    }
}
