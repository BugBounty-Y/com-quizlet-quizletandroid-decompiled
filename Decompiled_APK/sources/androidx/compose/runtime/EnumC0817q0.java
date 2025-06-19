package androidx.compose.runtime;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.runtime.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0817q0 {
    public static final EnumC0817q0 a;
    public static final EnumC0817q0 b;
    public static final EnumC0817q0 c;
    public static final EnumC0817q0 d;
    public static final EnumC0817q0 e;
    public static final EnumC0817q0 f;
    public static final /* synthetic */ EnumC0817q0[] g;

    static {
        EnumC0817q0 enumC0817q0 = new EnumC0817q0("ShutDown", 0);
        a = enumC0817q0;
        EnumC0817q0 enumC0817q02 = new EnumC0817q0("ShuttingDown", 1);
        b = enumC0817q02;
        EnumC0817q0 enumC0817q03 = new EnumC0817q0("Inactive", 2);
        c = enumC0817q03;
        EnumC0817q0 enumC0817q04 = new EnumC0817q0("InactivePendingWork", 3);
        d = enumC0817q04;
        EnumC0817q0 enumC0817q05 = new EnumC0817q0("Idle", 4);
        e = enumC0817q05;
        EnumC0817q0 enumC0817q06 = new EnumC0817q0("PendingWork", 5);
        f = enumC0817q06;
        EnumC0817q0[] enumC0817q0Arr = {enumC0817q0, enumC0817q02, enumC0817q03, enumC0817q04, enumC0817q05, enumC0817q06};
        g = enumC0817q0Arr;
        AbstractC3328d.f(enumC0817q0Arr);
    }

    public static EnumC0817q0 valueOf(String str) {
        return (EnumC0817q0) Enum.valueOf(EnumC0817q0.class, str);
    }

    public static EnumC0817q0[] values() {
        return (EnumC0817q0[]) g.clone();
    }
}
