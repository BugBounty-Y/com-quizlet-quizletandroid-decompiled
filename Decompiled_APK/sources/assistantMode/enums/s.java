package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = r.class)
/* loaded from: classes.dex */
public final class s implements serialization.b {

    @NotNull
    public static final StudiableMetadataType$Companion Companion;
    public static final s b;
    public static final s c;
    public static final s d;
    public static final s e;
    public static final s f;
    public static final s g;
    public static final s h;
    public static final /* synthetic */ s[] i;
    public final int a;

    static {
        s sVar = new s("ALTERNATIVE_QUESTIONS", 0, 1);
        b = sVar;
        s sVar2 = new s("FILL_IN_THE_BLANK_KEYPHRASES", 1, 2);
        c = sVar2;
        s sVar3 = new s("ITEM_DIFFICULTY", 2, 3);
        s sVar4 = new s("ML_DISTRACTORS", 3, 4);
        d = sVar4;
        s sVar5 = new s("CARD_SIDE_QUESTION_TYPE_RECOMMENDATIONS", 4, 5);
        e = sVar5;
        s sVar6 = new s("PARSED_MULTIPLE_CHOICE_QUESTION", 5, 6);
        f = sVar6;
        s sVar7 = new s("CARD_EXPLANATIONS", 6, 7);
        s sVar8 = new s("MCQ_EXPLANATIONS", 7, 8);
        s sVar9 = new s("MULTIPLE_CHOICE_SELECT_ALL_THAT_APPLY", 8, 9);
        g = sVar9;
        s sVar10 = new s("FILL_IN_THE_BLANK_MULTIPLE_CHOICE", 9, 10);
        h = sVar10;
        s[] sVarArr = {sVar, sVar2, sVar3, sVar4, sVar5, sVar6, sVar7, sVar8, sVar9, sVar10};
        i = sVarArr;
        AbstractC3328d.f(sVarArr);
        Companion = new StudiableMetadataType$Companion();
    }

    public s(String str, int i2, int i3) {
        this.a = i3;
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) i.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
