package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class E implements kmppUtils.bitmasks.a {

    @NotNull
    public static final D Companion;
    public static final E b;
    public static final E c;
    public static final E d;
    public static final /* synthetic */ E[] e;
    public final int a;

    static {
        E e2 = new E("UNKNOWN", 0, 0);
        E e3 = new E("WORD", 1, 1);
        b = e3;
        E e4 = new E("DEFINITION", 2, 2);
        c = e4;
        E e5 = new E("CATEGORY", 3, 3);
        E e6 = new E("LOCATION", 4, 4);
        d = e6;
        E[] eArr = {e2, e3, e4, e5, e6};
        e = eArr;
        AbstractC3328d.f(eArr);
        Companion = new D();
    }

    public E(String str, int i, int i2) {
        this.a = i2;
    }

    public static E valueOf(String str) {
        return (E) Enum.valueOf(E.class, str);
    }

    public static E[] values() {
        return (E[]) e.clone();
    }

    @Override // kmppUtils.bitmasks.a
    public final int a() {
        return (int) (1 << this.a);
    }
}
