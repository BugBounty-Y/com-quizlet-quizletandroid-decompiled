package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class M0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ M0[] $VALUES;

    @NotNull
    public static final L0 Companion;
    public static final M0 KNOWLEDGE_GRAPH_ML;
    public static final M0 KNOWLEDGE_GRAPH_SME;
    public static final M0 NONE;
    public static final M0 PEER_ACTIVITY;
    public static final M0 TEXTBOOK_LLM;
    public static final M0 TEXTBOOK_SME;
    private final int value;

    static {
        M0 m0 = new M0("NONE", 0, 0);
        NONE = m0;
        M0 m02 = new M0("TEXTBOOK_LLM", 1, 1);
        TEXTBOOK_LLM = m02;
        M0 m03 = new M0("TEXTBOOK_SME", 2, 2);
        TEXTBOOK_SME = m03;
        M0 m04 = new M0("PEER_ACTIVITY", 3, 3);
        PEER_ACTIVITY = m04;
        M0 m05 = new M0("KNOWLEDGE_GRAPH_SME", 4, 4);
        KNOWLEDGE_GRAPH_SME = m05;
        M0 m06 = new M0("KNOWLEDGE_GRAPH_ML", 5, 5);
        KNOWLEDGE_GRAPH_ML = m06;
        M0[] m0Arr = {m0, m02, m03, m04, m05, m06};
        $VALUES = m0Arr;
        $ENTRIES = AbstractC3328d.f(m0Arr);
        Companion = new L0();
    }

    public M0(String str, int i, int i2) {
        this.value = i2;
    }

    public static M0 valueOf(String str) {
        return (M0) Enum.valueOf(M0.class, str);
    }

    public static M0[] values() {
        return (M0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
