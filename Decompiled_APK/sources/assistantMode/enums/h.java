package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = C1453g.class)
/* loaded from: classes.dex */
public final class h implements serialization.b {

    @NotNull
    public static final OptionGenerationSource$Companion Companion;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final h e;
    public static final h f;
    public static final /* synthetic */ h[] g;
    public final int a;

    static {
        h hVar = new h("KEY", 0, 1);
        b = hVar;
        h hVar2 = new h("KMP_UGC_INPUT", 1, 2);
        c = hVar2;
        h hVar3 = new h("UGC_PARSED", 2, 3);
        d = hVar3;
        h hVar4 = new h("KMP_ALGO", 3, 4);
        e = hVar4;
        h hVar5 = new h("ML", 4, 5);
        f = hVar5;
        h[] hVarArr = {hVar, hVar2, hVar3, hVar4, hVar5};
        g = hVarArr;
        AbstractC3328d.f(hVarArr);
        Companion = new OptionGenerationSource$Companion();
    }

    public h(String str, int i, int i2) {
        this.a = i2;
    }

    public static i a(h hVar) {
        return new i(hVar, hVar.toString());
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) g.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }

    @Override // java.lang.Enum
    public final String toString() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "key";
        }
        if (iOrdinal == 1) {
            return "kmp_ugc_input";
        }
        if (iOrdinal == 2) {
            return "ugc_parsed";
        }
        if (iOrdinal == 3) {
            return "kmp_algo";
        }
        if (iOrdinal == 4) {
            return "ml";
        }
        throw new NoWhenBranchMatchedException();
    }
}
