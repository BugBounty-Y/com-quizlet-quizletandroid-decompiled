package androidx.work;

import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.work.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1440n implements Executor {
    public static final EnumC1440n a;
    public static final /* synthetic */ EnumC1440n[] b;

    static {
        EnumC1440n enumC1440n = new EnumC1440n("INSTANCE", 0);
        a = enumC1440n;
        b = new EnumC1440n[]{enumC1440n};
    }

    public static EnumC1440n valueOf(String str) {
        return (EnumC1440n) Enum.valueOf(EnumC1440n.class, str);
    }

    public static EnumC1440n[] values() {
        return (EnumC1440n[]) b.clone();
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable command) {
        Intrinsics.checkNotNullParameter(command, "command");
        command.run();
    }

    @Override // java.lang.Enum
    public final String toString() {
        return "DirectExecutor";
    }
}
