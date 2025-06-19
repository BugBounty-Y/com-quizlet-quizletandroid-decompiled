package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class Kv implements Executor {
    public static final Kv a;
    public static final /* synthetic */ Kv[] b;

    static {
        Kv kv = new Kv("INSTANCE", 0);
        a = kv;
        b = new Kv[]{kv};
    }

    public static Kv[] values() {
        return (Kv[]) b.clone();
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        runnable.run();
    }

    @Override // java.lang.Enum
    public final String toString() {
        return "MoreExecutors.directExecutor()";
    }
}
