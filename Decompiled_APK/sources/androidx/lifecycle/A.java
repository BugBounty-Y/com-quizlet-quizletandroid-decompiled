package androidx.lifecycle;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class A {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ A[] $VALUES;

    @NotNull
    public static final C1263y Companion;
    public static final A ON_ANY;
    public static final A ON_CREATE;
    public static final A ON_DESTROY;
    public static final A ON_PAUSE;
    public static final A ON_RESUME;
    public static final A ON_START;
    public static final A ON_STOP;

    static {
        A a = new A("ON_CREATE", 0);
        ON_CREATE = a;
        A a2 = new A("ON_START", 1);
        ON_START = a2;
        A a3 = new A("ON_RESUME", 2);
        ON_RESUME = a3;
        A a4 = new A("ON_PAUSE", 3);
        ON_PAUSE = a4;
        A a5 = new A("ON_STOP", 4);
        ON_STOP = a5;
        A a6 = new A("ON_DESTROY", 5);
        ON_DESTROY = a6;
        A a7 = new A("ON_ANY", 6);
        ON_ANY = a7;
        A[] aArr = {a, a2, a3, a4, a5, a6, a7};
        $VALUES = aArr;
        $ENTRIES = AbstractC3328d.f(aArr);
        Companion = new C1263y();
    }

    public static A valueOf(String str) {
        return (A) Enum.valueOf(A.class, str);
    }

    public static A[] values() {
        return (A[]) $VALUES.clone();
    }

    public final B a() {
        switch (AbstractC1264z.a[ordinal()]) {
            case 1:
            case 2:
                return B.c;
            case 3:
            case 4:
                return B.d;
            case 5:
                return B.e;
            case 6:
                return B.a;
            case 7:
                throw new IllegalArgumentException(this + " has no target state");
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
