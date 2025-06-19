package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class r {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ r[] $VALUES;
    public static final r BISMARCK;
    public static final r BLOCKS;
    public static final r CHARMS;

    @NotNull
    public static final C4512q Companion;
    public static final r FLASHCARDS;
    public static final r FLIP;
    public static final r GAMES_HUB;
    public static final r GRAVITY;
    public static final r LEARNING_ASSISTANT;
    public static final r LOCATE;
    public static final r MICROSCATTER;
    public static final r MOBILE_CARDS;
    public static final r MOBILE_SCATTER;
    public static final r MOBILE_WRITE;
    public static final r MULTIPLAYER;
    public static final r QCHAT;
    public static final r REVIEW;
    public static final r SCATTER;
    public static final r SINGLE_PLAYER_BLAST;
    public static final r SPACE_RACE;
    public static final r SPELLER;
    public static final r TEST;
    public static final r VOICE_RACE;
    public static final r VOICE_SCATTER;
    public static final r WRITE;

    @NotNull
    private final String value;

    static {
        r rVar = new r("WRITE", 0, "learn");
        WRITE = rVar;
        r rVar2 = new r("FLASHCARDS", 1, "flashcards");
        FLASHCARDS = rVar2;
        r rVar3 = new r("TEST", 2, "test");
        TEST = rVar3;
        r rVar4 = new r("SPACE_RACE", 3, "space_race");
        SPACE_RACE = rVar4;
        r rVar5 = new r("SCATTER", 4, "scatter");
        SCATTER = rVar5;
        r rVar6 = new r("VOICE_RACE", 5, "voice_race");
        VOICE_RACE = rVar6;
        r rVar7 = new r("VOICE_SCATTER", 6, "voice_scatter");
        VOICE_SCATTER = rVar7;
        r rVar8 = new r("SPELLER", 7, "speller");
        SPELLER = rVar8;
        r rVar9 = new r("BISMARCK", 8, "bismarck");
        BISMARCK = rVar9;
        r rVar10 = new r("MOBILE_CARDS", 9, "mobile_cards");
        MOBILE_CARDS = rVar10;
        r rVar11 = new r("MOBILE_WRITE", 10, "mobile_learn");
        MOBILE_WRITE = rVar11;
        r rVar12 = new r("MOBILE_SCATTER", 11, "mobile_scatter");
        MOBILE_SCATTER = rVar12;
        r rVar13 = new r("GRAVITY", 12, "gravity");
        GRAVITY = rVar13;
        r rVar14 = new r("MICROSCATTER", 13, "microscatter");
        MICROSCATTER = rVar14;
        r rVar15 = new r("REVIEW", 14, "review");
        REVIEW = rVar15;
        r rVar16 = new r("MULTIPLAYER", 15, "multiplayer");
        MULTIPLAYER = rVar16;
        r rVar17 = new r("LEARNING_ASSISTANT", 16, "learning_assistant");
        LEARNING_ASSISTANT = rVar17;
        r rVar18 = new r("LOCATE", 17, "locate");
        LOCATE = rVar18;
        r rVar19 = new r("QCHAT", 18, "q_chat");
        QCHAT = rVar19;
        r rVar20 = new r("GAMES_HUB", 19, "games_hub");
        GAMES_HUB = rVar20;
        r rVar21 = new r("BLOCKS", 20, "blocks");
        BLOCKS = rVar21;
        r rVar22 = new r("SINGLE_PLAYER_BLAST", 21, "single_player_blast");
        SINGLE_PLAYER_BLAST = rVar22;
        r rVar23 = new r("FLIP", 22, "flip");
        FLIP = rVar23;
        r rVar24 = new r("CHARMS", 23, "charms");
        CHARMS = rVar24;
        r[] rVarArr = {rVar, rVar2, rVar3, rVar4, rVar5, rVar6, rVar7, rVar8, rVar9, rVar10, rVar11, rVar12, rVar13, rVar14, rVar15, rVar16, rVar17, rVar18, rVar19, rVar20, rVar21, rVar22, rVar23, rVar24};
        $VALUES = rVarArr;
        $ENTRIES = AbstractC3328d.f(rVarArr);
        Companion = new C4512q();
    }

    public r(String str, int i, String str2) {
        this.value = str2;
    }

    public static r valueOf(String str) {
        return (r) Enum.valueOf(r.class, str);
    }

    public static r[] values() {
        return (r[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
