package com.quizlet.quizletandroid.braze.events;

import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[G1.values().length];
        try {
            iArr[G1.SET.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[G1.FOLDER.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[G1.PREP_PACK.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
        int[] iArr2 = new int[A1.values().length];
        try {
            iArr2[A1.WRITE.ordinal()] = 1;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr2[A1.FLASHCARDS.ordinal()] = 2;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr2[A1.TEST.ordinal()] = 3;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[A1.SPACE_RACE.ordinal()] = 4;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr2[A1.SCATTER.ordinal()] = 5;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            iArr2[A1.VOICE_RACE.ordinal()] = 6;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            iArr2[A1.VOICE_SCATTER.ordinal()] = 7;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            iArr2[A1.SPELLER.ordinal()] = 8;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            iArr2[A1.BISMARCK.ordinal()] = 9;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            iArr2[A1.MOBILE_CARDS.ordinal()] = 10;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            iArr2[A1.MOBILE_WRITE.ordinal()] = 11;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            iArr2[A1.MOBILE_SCATTER.ordinal()] = 12;
        } catch (NoSuchFieldError unused15) {
        }
        try {
            iArr2[A1.GRAVITY.ordinal()] = 13;
        } catch (NoSuchFieldError unused16) {
        }
        try {
            iArr2[A1.MICROSCATTER.ordinal()] = 14;
        } catch (NoSuchFieldError unused17) {
        }
        try {
            iArr2[A1.REVIEW.ordinal()] = 15;
        } catch (NoSuchFieldError unused18) {
        }
        try {
            iArr2[A1.MULTIPLAYER.ordinal()] = 16;
        } catch (NoSuchFieldError unused19) {
        }
        try {
            iArr2[A1.LEARNING_ASSISTANT.ordinal()] = 17;
        } catch (NoSuchFieldError unused20) {
        }
        try {
            iArr2[A1.LOCATE.ordinal()] = 18;
        } catch (NoSuchFieldError unused21) {
        }
        try {
            iArr2[A1.QCHAT.ordinal()] = 19;
        } catch (NoSuchFieldError unused22) {
        }
        try {
            iArr2[A1.GAMES_HUB.ordinal()] = 20;
        } catch (NoSuchFieldError unused23) {
        }
        try {
            iArr2[A1.BLOCKS.ordinal()] = 21;
        } catch (NoSuchFieldError unused24) {
        }
        try {
            iArr2[A1.SINGLE_PLAYER_BLAST.ordinal()] = 22;
        } catch (NoSuchFieldError unused25) {
        }
        try {
            iArr2[A1.FLIP.ordinal()] = 23;
        } catch (NoSuchFieldError unused26) {
        }
        try {
            iArr2[A1.CHARMS.ordinal()] = 24;
        } catch (NoSuchFieldError unused27) {
        }
        b = iArr2;
    }
}
