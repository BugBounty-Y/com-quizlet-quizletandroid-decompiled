package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = B.class)
/* loaded from: classes.dex */
public final class C implements serialization.b {

    @NotNull
    public static final TaskSequence$Companion Companion;
    public static final C b;
    public static final C c;
    public static final C d;
    public static final C e;
    public static final C f;
    public static final C g;
    public static final /* synthetic */ C[] h;
    public final int a;

    static {
        C c2 = new C("CHALLENGE_LOW", 0, 0);
        b = c2;
        C c3 = new C("CHALLENGE_HIGH", 1, 1);
        c = c3;
        C c4 = new C("MEMORIZATION_LOW", 2, 4);
        d = c4;
        C c5 = new C("MEMORIZATION_HIGH", 3, 5);
        e = c5;
        C c6 = new C("UNDERSTANDING_LOW", 4, 6);
        f = c6;
        C c7 = new C("UNDERSTANDING_HIGH", 5, 7);
        g = c7;
        C[] cArr = {c2, c3, c4, c5, c6, c7};
        h = cArr;
        AbstractC3328d.f(cArr);
        Companion = new TaskSequence$Companion();
    }

    public C(String str, int i, int i2) {
        this.a = i2;
    }

    public static C valueOf(String str) {
        return (C) Enum.valueOf(C.class, str);
    }

    public static C[] values() {
        return (C[]) h.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
