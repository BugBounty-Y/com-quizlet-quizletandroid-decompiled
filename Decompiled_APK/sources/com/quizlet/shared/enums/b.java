package com.quizlet.shared.enums;

import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = a.class)
/* loaded from: classes3.dex */
public final class b implements serialization.b {

    @NotNull
    public static final ExplanationSubject$Companion Companion;
    public static final /* synthetic */ b[] b;
    public final int a;

    static {
        b[] bVarArr = {new b("MATH", 0, 2), new b("ALGEBRA", 1, 3), new b("PREALGEBRA", 2, 4), new b("CALCULUS", 3, 5), new b("TRIGONOMETRY", 4, 6), new b("GEOMETRY", 5, 7), new b("PRECALCULUS", 6, 10), new b("ALGEBRA2", 7, 13), new b("DISCRETE_MATH", 8, 14), new b("STATISTICS", 9, 16), new b("SCIENCE", 10, 17), new b("PHYSICS", 11, 18), new b("HISTORY", 12, 19), new b("US_HISTORY", 13, 21), new b("ENGLISH", 14, 22), new b("NOVEL", 15, 23), new b("CHEMISTRY", 16, 24), new b("POEM", 17, 25), new b("PLAY", 18, 26), new b("AUTOBIOGRAPHY", 19, 27), new b("SHORT_STORY", 20, 28), new b("BIOLOGY", 21, 29), new b("COMPUTER_SCIENCE", 22, 30), new b("EUROPEAN_HISTORY", 23, 31), new b("WORLD_HISTORY", 24, 32), new b("US_GOVERNMENT", 25, 33), new b("HUMANITIES", 26, 34), new b("ANIMALS", 27, 35), new b("MUSIC", 28, 36), new b("SAT", 29, 37), new b("CRITICAL_READING", 30, 39), new b("MOVIES", 31, 40), new b("BUSINESS_STUDIES", 32, 41), new b("AP", 33, 42), new b("LINEAR_ALGEBRA", 34, 43), new b("DIFFERENTIAL_EQUATIONS", 35, 44), new b("PHYSICAL_SCIENCE", 36, 45), new b("COLLEGE_ALGEBRA", 37, 46), new b("FOREIGN_LANGUAGES", 38, 47), new b("SPANISH", 39, 48), new b("FRENCH", 40, 49), new b("GERMAN", 41, 50), new b("BUSINESS_MATH", 42, 51), new b("ECONOMICS", 43, 52), new b("EARTH_SCIENCE", 44, 53), new b("OTHER", 45, 54), new b("GEOGRAPHY", 46, 55), new b("ENGINEERING", 47, 56), new b("ANATOMY_AND_PHYSIOLOGY", 48, 57), new b("HEALTH", 49, 58), new b("ABSTRACT_ALGEBRA", 50, 59), new b("ADVANCED_MATH", 51, 60), new b("COMPLEX_VARIABLES", 52, 61), new b("FINITE_MATH", 53, 62), new b("ANALYSIS", 54, 63), new b("PROBABILITY", 55, 64), new b("ASTRONOMY", 56, 65), new b("EDUCATION", 57, 66), new b("OCEANOGRAPHY", 58, 67), new b("ORGANIC_CHEMISTRY", 59, 68), new b("INTEGRATED_MATH", 60, 69), new b("VOCABULARY", 61, 70), new b("LITERATURE", 62, 71), new b("ACCOUNTING", 63, 72), new b("OTHER_LANGUAGES", 64, 73), new b("LATIN", 65, 74), new b("INTERNATIONAL_BACCALAUREATE", 66, 75), new b("SOLVING_EQUATIONS", 67, 76), new b("UPPER_LEVEL_MATH", 68, 77), new b("HIGH_SCHOOL_MATH", 69, 78), new b("SOCIAL_SCIENCES", 70, 79), new b("LITERATURE_AND_ENGLISH", 71, 80), new b("PSYCHOLOGY", 72, 81), new b("SOCIOLOGY", 73, 82), new b("ENVIRONMENTAL_SCIENCE", 74, 83), new b("POLITICAL_SCIENCE", 75, 84), new b("ANTHROPOLOGY", 76, 85), new b("MANAGEMENT", 77, 86), new b("VOCATIONAL", 78, 87), new b("BUSINESS", 79, 88), new b("MARKETING", 80, 89), new b("FINANCE", 81, 90), new b("LINGUISTICS", 82, 91), new b("ART", 83, 92), new b("FILM", 84, 93), new b("A_LEVEL", 85, 94), new b("COLLEGE_PREP", 86, 95), new b("ABNORMAL_PSYCHOLOGY", 87, 96), new b("ELECTRICAL_ENGINEERING", 88, 98), new b("MECHANICAL_ENGINEERING", 89, 99), new b("MATH_FOUNDATIONS", 90, 100), new b("MATERIALS_SCIENCE", 91, 101), new b("ADVERTISING", 92, 102), new b("SOFTWARE_ENGINEERING", 93, 103), new b("CIVIL_LAW", 94, 104), new b("CIVICS", 95, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED), new b("ADMINISTRATIVE_LAW", 96, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF), new b("PUBLIC_HEALTH", 97, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED), new b("GENETICS", 98, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY), new b("GEOLOGY", 99, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION), new b("ECONOMETRICS", 100, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED), new b("MANAGERIAL_ECONOMICS", 101, 111), new b("BIOTECHNOLOGY", 102, ContentType.LONG_FORM_ON_DEMAND), new b("MACROECONOMICS", 103, ContentType.LIVE), new b("MICROBIOLOGY", 104, 114), new b("MOLECULAR_BIOLOGY", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED, 115), new b("COMPARATIVE_LAW", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF, 116), new b("ETHICS", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 142), new b("CARDIOLOGY", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, 143), new b("COGNITIVE_PSYCHOLOGY", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION, 144), new b("CRIMINAL_LAW", OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED, 145), new b("CIVIL_ENGINEERING", 111, 146), new b("COMPUTER_ARCHITECTURE", ContentType.LONG_FORM_ON_DEMAND, 147), new b("BIOLOGICAL_PSYCHOLOGY", ContentType.LIVE, 148), new b("ECOLOGY", 114, 150), new b("CELL_BIOLOGY", 115, 151), new b("BIOLOGICAL_ANTHROPOLOGY", 116, 152), new b("NEUROSCIENCE", 117, 153), new b("SPORTS", 118, 154), new b("GEOGRAPHY_OF_NORTH_AMERICA", 119, 155), new b("NUTRITION", 120, 156), new b("MICROECONOMICS", ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND, 157), new b("SCIENTIFIC_HISTORY", ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND, 158), new b("HUMAN_BIOLOGY", ContentType.USER_GENERATED_LIVE, 159), new b("INORGANIC_CHEMISTRY", 124, 160), new b("LIFE_SCIENCE", 125, 161), new b("INTERNATIONAL_ECONOMICS", 126, 162), new b("IMMUNOLOGY", 127, 163), new b("MUSIC_THEORY", 128, 164), new b("MARINE_BIOLOGY", 129, 165), new b("MODERN_HISTORY", 130, 166), new b("OPTOMETRY", 131, 167), new b("PATHOLOGY", 132, 168), new b("ANIMAL_SCIENCE", 133, 169), new b("PSYCHIATRY", 134, 170), new b("ANCIENT_HISTORY", 135, 171)};
        b = bVarArr;
        AbstractC3328d.f(bVarArr);
        Companion = new ExplanationSubject$Companion();
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
