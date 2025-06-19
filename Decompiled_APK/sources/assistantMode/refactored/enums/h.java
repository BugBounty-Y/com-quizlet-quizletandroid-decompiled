package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = g.class)
/* loaded from: classes.dex */
public final class h implements serialization.b {

    @NotNull
    public static final MediaType$Companion Companion;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final h e;
    public static final h f;
    public static final /* synthetic */ h[] g;
    public final int a;

    static {
        h hVar = new h("TEXT", 0, 1);
        b = hVar;
        h hVar2 = new h("IMAGE", 1, 2);
        c = hVar2;
        h hVar3 = new h("VIDEO", 2, 3);
        d = hVar3;
        h hVar4 = new h("AUDIO", 3, 4);
        e = hVar4;
        h hVar5 = new h("DIAGRAM_SHAPE", 4, 5);
        f = hVar5;
        h[] hVarArr = {hVar, hVar2, hVar3, hVar4, hVar5};
        g = hVarArr;
        AbstractC3328d.f(hVarArr);
        Companion = new MediaType$Companion();
    }

    public h(String str, int i, int i2) {
        this.a = i2;
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
}
