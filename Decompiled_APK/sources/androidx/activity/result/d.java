package androidx.activity.result;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final a a;
    public final androidx.activity.result.contract.a b;

    public d(androidx.activity.result.contract.a contract, a callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        Intrinsics.checkNotNullParameter(contract, "contract");
        this.a = callback;
        this.b = contract;
    }
}
