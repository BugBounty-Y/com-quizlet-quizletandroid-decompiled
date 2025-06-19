package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = l.class)
/* loaded from: classes.dex */
public final class m implements serialization.f {

    @NotNull
    public static final StudiableCardSideLabel$Companion Companion;
    public static final m b;
    public static final m c;
    public static final m d;
    public static final /* synthetic */ m[] e;
    public final String a;

    static {
        m mVar = new m("WORD", 0, "word");
        b = mVar;
        m mVar2 = new m("DEFINITION", 1, "definition");
        c = mVar2;
        m mVar3 = new m("LOCATION", 2, "location");
        d = mVar3;
        m[] mVarArr = {mVar, mVar2, mVar3};
        e = mVarArr;
        AbstractC3328d.f(mVarArr);
        Companion = new StudiableCardSideLabel$Companion();
    }

    public m(String str, int i, String str2) {
        this.a = str2;
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) e.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
