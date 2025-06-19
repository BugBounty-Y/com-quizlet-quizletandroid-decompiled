package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = t.class)
/* loaded from: classes.dex */
public final class u implements serialization.b {

    @NotNull
    public static final StudyMode$Companion Companion;
    public static final u b;
    public static final u c;
    public static final u d;
    public static final u e;
    public static final u f;
    public static final u g;
    public static final u h;
    public static final u i;
    public static final u j;
    public static final u k;
    public static final u l;
    public static final u m;
    public static final u n;
    public static final u o;
    public static final u p;
    public static final u q;
    public static final u r;
    public static final u s;
    public static final /* synthetic */ u[] t;
    public final int a;

    static {
        u uVar = new u("WRITE", 0, 1);
        b = uVar;
        u uVar2 = new u("FLASHCARDS", 1, 2);
        c = uVar2;
        u uVar3 = new u("TEST", 2, 3);
        d = uVar3;
        u uVar4 = new u("SPACE_RACE", 3, 4);
        e = uVar4;
        u uVar5 = new u("SCATTER", 4, 5);
        f = uVar5;
        u uVar6 = new u("VOICE_RACE", 5, 6);
        g = uVar6;
        u uVar7 = new u("VOICE_SCATTER", 6, 7);
        h = uVar7;
        u uVar8 = new u("SPELLER", 7, 8);
        i = uVar8;
        u uVar9 = new u("BISMARCK", 8, 9);
        j = uVar9;
        u uVar10 = new u("MOBILE_CARDS", 9, 10);
        k = uVar10;
        u uVar11 = new u("MOBILE_WRITE", 10, 11);
        l = uVar11;
        u uVar12 = new u("MOBILE_SCATTER", 11, 12);
        m = uVar12;
        u uVar13 = new u("GRAVITY", 12, 13);
        n = uVar13;
        u uVar14 = new u("MICROSCATTER", 13, 14);
        o = uVar14;
        u uVar15 = new u("REVIEW", 14, 15);
        p = uVar15;
        u uVar16 = new u("MULTIPLAYER", 15, 16);
        q = uVar16;
        u uVar17 = new u("LEARNING_ASSISTANT", 16, 17);
        r = uVar17;
        u uVar18 = new u("LOCATE", 17, 18);
        s = uVar18;
        u[] uVarArr = {uVar, uVar2, uVar3, uVar4, uVar5, uVar6, uVar7, uVar8, uVar9, uVar10, uVar11, uVar12, uVar13, uVar14, uVar15, uVar16, uVar17, uVar18, new u("LIVE_WITH_FRIENDS", 18, 19), new u("QCHAT", 19, 20)};
        t = uVarArr;
        AbstractC3328d.f(uVarArr);
        Companion = new StudyMode$Companion();
    }

    public u(String str, int i2, int i3) {
        this.a = i3;
    }

    public static u valueOf(String str) {
        return (u) Enum.valueOf(u.class, str);
    }

    public static u[] values() {
        return (u[]) t.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
