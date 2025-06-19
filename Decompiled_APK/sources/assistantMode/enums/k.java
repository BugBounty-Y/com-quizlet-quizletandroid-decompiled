package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = j.class)
/* loaded from: classes.dex */
public final class k implements kmppUtils.bitmasks.a, serialization.b {

    @NotNull
    public static final QuestionType$Companion Companion;
    public static final k b;
    public static final k c;
    public static final k d;
    public static final k e;
    public static final k f;
    public static final k g;
    public static final k h;
    public static final k i;
    public static final k j;
    public static final k k;
    public static final k l;
    public static final k m;
    public static final k n;
    public static final /* synthetic */ k[] o;
    public final int a;

    static {
        k kVar = new k("Written", 0, (int) 1);
        b = kVar;
        k kVar2 = new k("Matching", 1, (int) 2);
        c = kVar2;
        k kVar3 = new k("MultipleChoice", 2, (int) 4);
        d = kVar3;
        k kVar4 = new k("TrueFalse", 3, (int) 8);
        e = kVar4;
        k kVar5 = new k("RevealSelfAssessment", 4, (int) 16);
        f = kVar5;
        k kVar6 = new k("MultipleChoiceWithNoneOption", 5, (int) 32);
        g = kVar6;
        k kVar7 = new k("CopyAnswer", 6, (int) 64);
        h = kVar7;
        k kVar8 = new k("Spelling", 7, (int) 128);
        i = kVar8;
        k kVar9 = new k("FlashcardWithoutResponse", 8, (int) 256);
        j = kVar9;
        k kVar10 = new k("MixedOptionMatching", 9, (int) 512);
        k = kVar10;
        k kVar11 = new k("FillInTheBlank", 10, (int) 1024);
        l = kVar11;
        k kVar12 = new k("MultipleChoiceSelectAllThatApply", 11, (int) 2048);
        m = kVar12;
        k kVar13 = new k("FillInTheBlankMultipleChoice", 12, (int) 4096);
        n = kVar13;
        k[] kVarArr = {kVar, kVar2, kVar3, kVar4, kVar5, kVar6, kVar7, kVar8, kVar9, kVar10, kVar11, kVar12, kVar13};
        o = kVarArr;
        AbstractC3328d.f(kVarArr);
        Companion = new QuestionType$Companion();
    }

    public k(String str, int i2, int i3) {
        this.a = i3;
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) o.clone();
    }

    @Override // kmppUtils.bitmasks.a
    public final int a() {
        return this.a;
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
