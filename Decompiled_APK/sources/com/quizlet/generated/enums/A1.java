package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class A1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ A1[] $VALUES;
    public static final A1 BISMARCK;
    public static final A1 BLOCKS;
    public static final A1 CHARMS;

    @NotNull
    public static final z1 Companion;
    public static final A1 FLASHCARDS;
    public static final A1 FLIP;
    public static final A1 GAMES_HUB;
    public static final A1 GRAVITY;
    public static final A1 LEARNING_ASSISTANT;
    public static final A1 LOCATE;
    public static final A1 MICROSCATTER;
    public static final A1 MOBILE_CARDS;
    public static final A1 MOBILE_SCATTER;
    public static final A1 MOBILE_WRITE;
    public static final A1 MULTIPLAYER;
    public static final A1 QCHAT;
    public static final A1 REVIEW;
    public static final A1 SCATTER;
    public static final A1 SINGLE_PLAYER_BLAST;
    public static final A1 SPACE_RACE;
    public static final A1 SPELLER;
    public static final A1 TEST;
    public static final A1 VOICE_RACE;
    public static final A1 VOICE_SCATTER;
    public static final A1 WRITE;
    private final int value;

    static {
        A1 a1 = new A1("WRITE", 0, 1);
        WRITE = a1;
        A1 a12 = new A1("FLASHCARDS", 1, 2);
        FLASHCARDS = a12;
        A1 a13 = new A1("TEST", 2, 3);
        TEST = a13;
        A1 a14 = new A1("SPACE_RACE", 3, 4);
        SPACE_RACE = a14;
        A1 a15 = new A1("SCATTER", 4, 5);
        SCATTER = a15;
        A1 a16 = new A1("VOICE_RACE", 5, 6);
        VOICE_RACE = a16;
        A1 a17 = new A1("VOICE_SCATTER", 6, 7);
        VOICE_SCATTER = a17;
        A1 a18 = new A1("SPELLER", 7, 8);
        SPELLER = a18;
        A1 a19 = new A1("BISMARCK", 8, 9);
        BISMARCK = a19;
        A1 a110 = new A1("MOBILE_CARDS", 9, 10);
        MOBILE_CARDS = a110;
        A1 a111 = new A1("MOBILE_WRITE", 10, 11);
        MOBILE_WRITE = a111;
        A1 a112 = new A1("MOBILE_SCATTER", 11, 12);
        MOBILE_SCATTER = a112;
        A1 a113 = new A1("GRAVITY", 12, 13);
        GRAVITY = a113;
        A1 a114 = new A1("MICROSCATTER", 13, 14);
        MICROSCATTER = a114;
        A1 a115 = new A1("REVIEW", 14, 15);
        REVIEW = a115;
        A1 a116 = new A1("MULTIPLAYER", 15, 16);
        MULTIPLAYER = a116;
        A1 a117 = new A1("LEARNING_ASSISTANT", 16, 17);
        LEARNING_ASSISTANT = a117;
        A1 a118 = new A1("LOCATE", 17, 18);
        LOCATE = a118;
        A1 a119 = new A1("QCHAT", 18, 20);
        QCHAT = a119;
        A1 a120 = new A1("GAMES_HUB", 19, 21);
        GAMES_HUB = a120;
        A1 a121 = new A1("BLOCKS", 20, 22);
        BLOCKS = a121;
        A1 a122 = new A1("SINGLE_PLAYER_BLAST", 21, 23);
        SINGLE_PLAYER_BLAST = a122;
        A1 a123 = new A1("FLIP", 22, 24);
        FLIP = a123;
        A1 a124 = new A1("CHARMS", 23, 25);
        CHARMS = a124;
        A1[] a1Arr = {a1, a12, a13, a14, a15, a16, a17, a18, a19, a110, a111, a112, a113, a114, a115, a116, a117, a118, a119, a120, a121, a122, a123, a124};
        $VALUES = a1Arr;
        $ENTRIES = AbstractC3328d.f(a1Arr);
        Companion = new z1();
    }

    public A1(String str, int i, int i2) {
        this.value = i2;
    }

    public static A1 valueOf(String str) {
        return (A1) Enum.valueOf(A1.class, str);
    }

    public static A1[] values() {
        return (A1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
