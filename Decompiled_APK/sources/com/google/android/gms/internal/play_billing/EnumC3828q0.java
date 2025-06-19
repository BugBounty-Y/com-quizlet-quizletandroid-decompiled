package com.google.android.gms.internal.play_billing;

import java.util.concurrent.Executor;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.play_billing.q0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC3828q0 implements Executor {
    public static final EnumC3828q0 a;
    public static final /* synthetic */ EnumC3828q0[] b;

    static {
        EnumC3828q0 enumC3828q0 = new EnumC3828q0("INSTANCE", 0);
        a = enumC3828q0;
        b = new EnumC3828q0[]{enumC3828q0};
    }

    public static EnumC3828q0[] values() {
        return (EnumC3828q0[]) b.clone();
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
