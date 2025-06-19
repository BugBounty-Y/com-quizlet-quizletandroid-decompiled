package com.quizlet.features.infra.basestudy.utils;

import assistantMode.enums.StudyPathKnowledgeLevel$Companion;
import assistantMode.enums.y;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;
    public static final /* synthetic */ int[] c;
    public static final /* synthetic */ int[] d;

    static {
        int[] iArr = new int[O1.values().length];
        try {
            iArr[O1.WORD.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[O1.DEFINITION.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[O1.LOCATION.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
        int[] iArr2 = new int[A1.values().length];
        try {
            iArr2[A1.LEARNING_ASSISTANT.ordinal()] = 1;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr2[A1.WRITE.ordinal()] = 2;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr2[A1.FLASHCARDS.ordinal()] = 3;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[A1.TEST.ordinal()] = 4;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr2[A1.SPACE_RACE.ordinal()] = 5;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            iArr2[A1.SCATTER.ordinal()] = 6;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            iArr2[A1.VOICE_RACE.ordinal()] = 7;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            iArr2[A1.VOICE_SCATTER.ordinal()] = 8;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            iArr2[A1.SPELLER.ordinal()] = 9;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            iArr2[A1.BISMARCK.ordinal()] = 10;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            iArr2[A1.MOBILE_CARDS.ordinal()] = 11;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            iArr2[A1.MOBILE_WRITE.ordinal()] = 12;
        } catch (NoSuchFieldError unused15) {
        }
        try {
            iArr2[A1.MOBILE_SCATTER.ordinal()] = 13;
        } catch (NoSuchFieldError unused16) {
        }
        try {
            iArr2[A1.GRAVITY.ordinal()] = 14;
        } catch (NoSuchFieldError unused17) {
        }
        try {
            iArr2[A1.MICROSCATTER.ordinal()] = 15;
        } catch (NoSuchFieldError unused18) {
        }
        try {
            iArr2[A1.REVIEW.ordinal()] = 16;
        } catch (NoSuchFieldError unused19) {
        }
        try {
            iArr2[A1.MULTIPLAYER.ordinal()] = 17;
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
        int[] iArr3 = new int[y.values().length];
        try {
            StudyPathKnowledgeLevel$Companion studyPathKnowledgeLevel$Companion = y.Companion;
            iArr3[2] = 1;
        } catch (NoSuchFieldError unused28) {
        }
        c = iArr3;
        int[] iArr4 = new int[com.quizlet.studiablemodels.assistantMode.a.values().length];
        try {
            com.quizlet.studiablemodels.assistantMode.a aVar = com.quizlet.studiablemodels.assistantMode.a.a;
            iArr4[0] = 1;
        } catch (NoSuchFieldError unused29) {
        }
        try {
            com.quizlet.studiablemodels.assistantMode.a aVar2 = com.quizlet.studiablemodels.assistantMode.a.a;
            iArr4[1] = 2;
        } catch (NoSuchFieldError unused30) {
        }
        try {
            com.quizlet.studiablemodels.assistantMode.a aVar3 = com.quizlet.studiablemodels.assistantMode.a.a;
            iArr4[2] = 3;
        } catch (NoSuchFieldError unused31) {
        }
        try {
            com.quizlet.studiablemodels.assistantMode.a aVar4 = com.quizlet.studiablemodels.assistantMode.a.a;
            iArr4[3] = 4;
        } catch (NoSuchFieldError unused32) {
        }
        d = iArr4;
    }
}
