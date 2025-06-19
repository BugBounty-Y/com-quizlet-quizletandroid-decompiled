package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4467b {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4467b[] $VALUES;
    public static final EnumC4467b COMPLETE_ROUND;
    public static final EnumC4467b CREATE;

    @NotNull
    public static final C4464a Companion;
    public static final EnumC4467b RANK_FIRST;
    public static final EnumC4467b REACH_END;
    public static final EnumC4467b STUDY;

    @NotNull
    private final String value;

    static {
        EnumC4467b enumC4467b = new EnumC4467b("COMPLETE_ROUND", 0, "CompleteRound");
        COMPLETE_ROUND = enumC4467b;
        EnumC4467b enumC4467b2 = new EnumC4467b("CREATE", 1, "Create");
        CREATE = enumC4467b2;
        EnumC4467b enumC4467b3 = new EnumC4467b("RANK_FIRST", 2, "RankFirst");
        RANK_FIRST = enumC4467b3;
        EnumC4467b enumC4467b4 = new EnumC4467b("REACH_END", 3, "ReachEnd");
        REACH_END = enumC4467b4;
        EnumC4467b enumC4467b5 = new EnumC4467b("STUDY", 4, "Study");
        STUDY = enumC4467b5;
        EnumC4467b[] enumC4467bArr = {enumC4467b, enumC4467b2, enumC4467b3, enumC4467b4, enumC4467b5};
        $VALUES = enumC4467bArr;
        $ENTRIES = AbstractC3328d.f(enumC4467bArr);
        Companion = new C4464a();
    }

    public EnumC4467b(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4467b valueOf(String str) {
        return (EnumC4467b) Enum.valueOf(EnumC4467b.class, str);
    }

    public static EnumC4467b[] values() {
        return (EnumC4467b[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
