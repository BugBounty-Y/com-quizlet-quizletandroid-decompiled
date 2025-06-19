package com.google.mlkit.common.sdkinternal;

import java.util.concurrent.Executor;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class k implements Executor {
    public static final k a;
    public static final /* synthetic */ k[] b;

    static {
        k kVar = new k("INSTANCE", 0);
        a = kVar;
        b = new k[]{kVar};
    }

    public static k[] values() {
        return (k[]) b.clone();
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        e.a().a.post(runnable);
    }
}
