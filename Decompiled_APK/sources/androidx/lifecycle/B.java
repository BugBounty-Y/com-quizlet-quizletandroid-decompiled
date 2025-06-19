package androidx.lifecycle;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class B {
    public static final B a;
    public static final B b;
    public static final B c;
    public static final B d;
    public static final B e;
    public static final /* synthetic */ B[] f;

    static {
        B b2 = new B("DESTROYED", 0);
        a = b2;
        B b3 = new B("INITIALIZED", 1);
        b = b3;
        B b4 = new B("CREATED", 2);
        c = b4;
        B b5 = new B("STARTED", 3);
        d = b5;
        B b6 = new B("RESUMED", 4);
        e = b6;
        B[] bArr = {b2, b3, b4, b5, b6};
        f = bArr;
        AbstractC3328d.f(bArr);
    }

    public static B valueOf(String str) {
        return (B) Enum.valueOf(B.class, str);
    }

    public static B[] values() {
        return (B[]) f.clone();
    }

    public final boolean a(B state) {
        Intrinsics.checkNotNullParameter(state, "state");
        return compareTo(state) >= 0;
    }
}
