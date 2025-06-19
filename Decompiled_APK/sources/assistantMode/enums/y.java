package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = x.class)
/* loaded from: classes.dex */
public final class y implements serialization.b {

    @NotNull
    public static final StudyPathKnowledgeLevel$Companion Companion;
    public static final y b;
    public static final y c;
    public static final y d;
    public static final /* synthetic */ y[] e;
    public static final /* synthetic */ kotlin.enums.b f;
    public final int a;

    static {
        y yVar = new y("LOW", 0, 0);
        b = yVar;
        y yVar2 = new y("MEDIUM", 1, 1);
        c = yVar2;
        y yVar3 = new y("HIGH", 2, 2);
        d = yVar3;
        y[] yVarArr = {yVar, yVar2, yVar3, new y("UNSURE", 3, 3)};
        e = yVarArr;
        f = AbstractC3328d.f(yVarArr);
        Companion = new StudyPathKnowledgeLevel$Companion();
    }

    public y(String str, int i, int i2) {
        this.a = i2;
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) e.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
