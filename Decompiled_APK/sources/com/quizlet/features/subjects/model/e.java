package com.quizlet.features.subjects.model;

import com.quizlet.generated.enums.I1;
import com.quizlet.generated.enums.K1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class e {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[I1.values().length];
        try {
            iArr[I1.ARTS_AND_HUMANITIES.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[I1.LANGUAGES.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[I1.MATH.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[I1.SCIENCE.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[I1.SOCIAL_SCIENCE.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        a = iArr;
        int[] iArr2 = new int[K1.values().length];
        try {
            iArr2[K1.HISTORY.ordinal()] = 1;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[K1.LINGUISTICS.ordinal()] = 2;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr2[K1.LITERATURE.ordinal()] = 3;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            iArr2[K1.ART_HISTORY.ordinal()] = 4;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            iArr2[K1.DANCE.ordinal()] = 5;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            iArr2[K1.VOCABULARY.ordinal()] = 6;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            iArr2[K1.VISUAL_ARTS.ordinal()] = 7;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            iArr2[K1.LITERATURE_AND_ENGLISH.ordinal()] = 8;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            iArr2[K1.THEATER.ordinal()] = 9;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            iArr2[K1.PHILOSOPHY.ordinal()] = 10;
        } catch (NoSuchFieldError unused15) {
        }
        try {
            iArr2[K1.FILM_AND_TV.ordinal()] = 11;
        } catch (NoSuchFieldError unused16) {
        }
        try {
            iArr2[K1.MUSIC.ordinal()] = 12;
        } catch (NoSuchFieldError unused17) {
        }
        try {
            iArr2[K1.ARTS_AND_HUMANITIES.ordinal()] = 13;
        } catch (NoSuchFieldError unused18) {
        }
        try {
            iArr2[K1.ENGLISH.ordinal()] = 14;
        } catch (NoSuchFieldError unused19) {
        }
        try {
            iArr2[K1.SPANISH.ordinal()] = 15;
        } catch (NoSuchFieldError unused20) {
        }
        try {
            iArr2[K1.GERMAN.ordinal()] = 16;
        } catch (NoSuchFieldError unused21) {
        }
        try {
            iArr2[K1.FRENCH.ordinal()] = 17;
        } catch (NoSuchFieldError unused22) {
        }
        try {
            iArr2[K1.CHINESE.ordinal()] = 18;
        } catch (NoSuchFieldError unused23) {
        }
        try {
            iArr2[K1.KOREAN.ordinal()] = 19;
        } catch (NoSuchFieldError unused24) {
        }
        try {
            iArr2[K1.JAPANESE.ordinal()] = 20;
        } catch (NoSuchFieldError unused25) {
        }
        try {
            iArr2[K1.LATIN.ordinal()] = 21;
        } catch (NoSuchFieldError unused26) {
        }
        try {
            iArr2[K1.OTHER_LANGUAGES.ordinal()] = 22;
        } catch (NoSuchFieldError unused27) {
        }
        try {
            iArr2[K1.MATH.ordinal()] = 23;
        } catch (NoSuchFieldError unused28) {
        }
        try {
            iArr2[K1.ARITHMETIC.ordinal()] = 24;
        } catch (NoSuchFieldError unused29) {
        }
        try {
            iArr2[K1.GEOMETRY.ordinal()] = 25;
        } catch (NoSuchFieldError unused30) {
        }
        try {
            iArr2[K1.MATH_NOTATION.ordinal()] = 26;
        } catch (NoSuchFieldError unused31) {
        }
        try {
            iArr2[K1.ALGEBRA.ordinal()] = 27;
        } catch (NoSuchFieldError unused32) {
        }
        try {
            iArr2[K1.DISCRETE_MATH.ordinal()] = 28;
        } catch (NoSuchFieldError unused33) {
        }
        try {
            iArr2[K1.MATH_FOUNDATIONS.ordinal()] = 29;
        } catch (NoSuchFieldError unused34) {
        }
        try {
            iArr2[K1.PROBABILITY.ordinal()] = 30;
        } catch (NoSuchFieldError unused35) {
        }
        try {
            iArr2[K1.STATISTICS.ordinal()] = 31;
        } catch (NoSuchFieldError unused36) {
        }
        try {
            iArr2[K1.APPLIED_MATH.ordinal()] = 32;
        } catch (NoSuchFieldError unused37) {
        }
        try {
            iArr2[K1.CALCULUS.ordinal()] = 33;
        } catch (NoSuchFieldError unused38) {
        }
        try {
            iArr2[K1.PHYSICS.ordinal()] = 34;
        } catch (NoSuchFieldError unused39) {
        }
        try {
            iArr2[K1.BIOLOGY.ordinal()] = 35;
        } catch (NoSuchFieldError unused40) {
        }
        try {
            iArr2[K1.EARTH_SCIENCE.ordinal()] = 36;
        } catch (NoSuchFieldError unused41) {
        }
        try {
            iArr2[K1.CHEMISTRY.ordinal()] = 37;
        } catch (NoSuchFieldError unused42) {
        }
        try {
            iArr2[K1.SPACE_SCIENCE.ordinal()] = 38;
        } catch (NoSuchFieldError unused43) {
        }
        try {
            iArr2[K1.COMPUTER_SCIENCE.ordinal()] = 39;
        } catch (NoSuchFieldError unused44) {
        }
        try {
            iArr2[K1.MEDICINE.ordinal()] = 40;
        } catch (NoSuchFieldError unused45) {
        }
        try {
            iArr2[K1.ENGINEERING.ordinal()] = 41;
        } catch (NoSuchFieldError unused46) {
        }
        try {
            iArr2[K1.WORLD_GEOGRAPHY.ordinal()] = 42;
        } catch (NoSuchFieldError unused47) {
        }
        try {
            iArr2[K1.LAW.ordinal()] = 43;
        } catch (NoSuchFieldError unused48) {
        }
        try {
            iArr2[K1.ANTHROPOLOGY.ordinal()] = 44;
        } catch (NoSuchFieldError unused49) {
        }
        try {
            iArr2[K1.BUSINESS.ordinal()] = 45;
        } catch (NoSuchFieldError unused50) {
        }
        try {
            iArr2[K1.SOCIOLOGY.ordinal()] = 46;
        } catch (NoSuchFieldError unused51) {
        }
        try {
            iArr2[K1.GEOGRAPHY.ordinal()] = 47;
        } catch (NoSuchFieldError unused52) {
        }
        try {
            iArr2[K1.ECONOMICS.ordinal()] = 48;
        } catch (NoSuchFieldError unused53) {
        }
        try {
            iArr2[K1.PSYCHOLOGY.ordinal()] = 49;
        } catch (NoSuchFieldError unused54) {
        }
        try {
            iArr2[K1.HUMAN_GEOGRAPHY.ordinal()] = 50;
        } catch (NoSuchFieldError unused55) {
        }
        b = iArr2;
    }
}
