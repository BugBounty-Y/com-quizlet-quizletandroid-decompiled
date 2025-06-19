package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.View;
import com.appsflyer.attribution.RequestError;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class G6 {
    public static com.google.firebase.crashlytics.internal.settings.d a(HashMap storedState) {
        Intrinsics.checkNotNullParameter(storedState, "storedState");
        Object obj = storedState.get("firstEventId");
        if (obj instanceof String) {
            Object obj2 = storedState.get("firstEventTimestamp");
            if (obj2 instanceof String) {
                Object obj3 = storedState.get(DBAnswerFields.Names.SESSION_ID);
                if (obj3 instanceof String) {
                    Object obj4 = storedState.get("previousSessionId");
                    if (!(obj4 instanceof String)) {
                        obj4 = null;
                    }
                    String str = obj4 instanceof String ? (String) obj4 : null;
                    Object obj5 = storedState.get("sessionIndex");
                    if (obj5 instanceof Integer) {
                        Object obj6 = storedState.get("userId");
                        if (obj6 instanceof String) {
                            Object obj7 = storedState.get("storageMechanism");
                            if (obj7 instanceof String) {
                                Object obj8 = storedState.get("eventIndex");
                                Integer num = obj8 instanceof Integer ? (Integer) obj8 : null;
                                Object obj9 = storedState.get("lastUpdate");
                                return new com.google.firebase.crashlytics.internal.settings.d((String) obj, (String) obj2, (String) obj3, str, ((Number) obj5).intValue(), (String) obj6, (String) obj7, num, obj9 instanceof Long ? (Long) obj9 : null);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static final void b(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        androidx.core.view.Z block = new androidx.core.view.Z(view, null);
        Intrinsics.checkNotNullParameter(block, "block");
        kotlin.sequences.h hVarA = kotlin.sequences.j.a(block);
        while (hVarA.hasNext()) {
            ArrayList arrayList = c((View) hVarA.next()).a;
            for (int i = kotlin.collections.B.i(arrayList); -1 < i; i--) {
                ((androidx.compose.ui.platform.U0) arrayList.get(i)).a.disposeComposition();
            }
        }
    }

    public static final androidx.customview.poolingcontainer.a c(View view) {
        androidx.customview.poolingcontainer.a aVar = (androidx.customview.poolingcontainer.a) view.getTag(R.id.pooling_container_listener_holder_tag);
        if (aVar != null) {
            return aVar;
        }
        androidx.customview.poolingcontainer.a aVar2 = new androidx.customview.poolingcontainer.a();
        view.setTag(R.id.pooling_container_listener_holder_tag, aVar2);
        return aVar2;
    }

    public static final int d(com.quizlet.generated.enums.D d) {
        com.quizlet.shared.enums.b bVar = null;
        Integer numValueOf = d != null ? Integer.valueOf(d.a()) : null;
        com.quizlet.shared.enums.b[] bVarArrValues = com.quizlet.shared.enums.b.values();
        int length = bVarArrValues.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            com.quizlet.shared.enums.b bVar2 = bVarArrValues[i];
            if (Integer.valueOf(bVar2.a).equals(numValueOf)) {
                bVar = bVar2;
                break;
            }
            i++;
        }
        if (bVar == null) {
            return R.string.explanation_subject_fallback;
        }
        switch (com.quizlet.features.infra.models.utils.a.a[bVar.ordinal()]) {
            case -1:
                return R.string.explanation_subject_fallback;
            case 0:
            default:
                throw new NoWhenBranchMatchedException();
            case 1:
                return R.string.explanation_subject_accounting;
            case 2:
                return R.string.explanation_subject_advanced_math;
            case 3:
                return R.string.explanation_subject_algebra;
            case 4:
                return R.string.explanation_subject_algebra2;
            case 5:
                return R.string.explanation_subject_anatomy_and_physiology;
            case 6:
                return R.string.explanation_subject_anthropology;
            case 7:
                return R.string.explanation_subject_astronomy;
            case 8:
                return R.string.explanation_subject_autobiography;
            case 9:
                return R.string.explanation_subject_biology;
            case 10:
                return R.string.explanation_subject_business_math;
            case 11:
                return R.string.explanation_subject_calculus;
            case 12:
                return R.string.explanation_subject_chemistry;
            case 13:
                return R.string.explanation_subject_college_algebra;
            case 14:
                return R.string.explanation_subject_computer_science;
            case 15:
                return R.string.explanation_subject_differential_equations;
            case 16:
                return R.string.explanation_subject_discrete_math;
            case 17:
                return R.string.explanation_subject_earth_science;
            case 18:
                return R.string.explanation_subject_economics;
            case 19:
                return R.string.explanation_subject_engineering;
            case 20:
                return R.string.explanation_subject_environmental_science;
            case 21:
                return R.string.explanation_subject_european_history;
            case EventType.WINDOW_STATE /* 22 */:
                return R.string.explanation_subject_foreign_languages;
            case EventType.AUDIO /* 23 */:
                return R.string.explanation_subject_french;
            case EventType.VIDEO /* 24 */:
                return R.string.explanation_subject_geography;
            case EventType.SUBS /* 25 */:
                return R.string.explanation_subject_geometry;
            case EventType.CDN /* 26 */:
                return R.string.explanation_subject_health;
            case 27:
                return R.string.explanation_subject_high_school_math;
            case 28:
                return R.string.explanation_subject_integrated_math;
            case 29:
                return R.string.explanation_subject_international_baccalaureate;
            case 30:
                return R.string.explanation_subject_latin;
            case 31:
                return R.string.explanation_subject_linear_algebra;
            case 32:
                return R.string.explanation_subject_literature;
            case 33:
                return R.string.explanation_subject_literature_and_english;
            case 34:
                return R.string.explanation_subject_management;
            case 35:
                return R.string.explanation_subject_math;
            case 36:
                return R.string.explanation_subject_novel;
            case 37:
                return R.string.explanation_subject_organic_chemistry;
            case 38:
                return R.string.explanation_subject_other;
            case 39:
                return R.string.explanation_subject_other_languages;
            case RequestError.NETWORK_FAILURE /* 40 */:
                return R.string.explanation_subject_physical_science;
            case RequestError.NO_DEV_KEY /* 41 */:
                return R.string.explanation_subject_physics;
            case 42:
                return R.string.explanation_subject_play;
            case 43:
                return R.string.explanation_subject_poem;
            case 44:
                return R.string.explanation_subject_political_science;
            case 45:
                return R.string.explanation_subject_prealgebra;
            case 46:
                return R.string.explanation_subject_precalculus;
            case 47:
                return R.string.explanation_subject_probability;
            case 48:
                return R.string.explanation_subject_psychology;
            case 49:
                return R.string.explanation_subject_science;
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                return R.string.explanation_subject_short_story;
            case 51:
                return R.string.explanation_subject_social_sciences;
            case 52:
                return R.string.explanation_subject_sociology;
            case 53:
                return R.string.explanation_subject_spanish;
            case 54:
                return R.string.explanation_subject_statistics;
            case 55:
                return R.string.explanation_subject_trigonometry;
            case 56:
                return R.string.explanation_subject_upper_level_math;
            case 57:
                return R.string.explanation_subject_us_government;
            case 58:
                return R.string.explanation_subject_us_history;
            case 59:
                return R.string.explanation_subject_vocabulary;
            case 60:
                return R.string.explanation_subject_world_history;
            case 61:
                return R.string.explanation_subject_history;
            case 62:
                return R.string.explanation_subject_english;
            case 63:
                return R.string.explanation_subject_humanities;
            case 64:
                return R.string.explanation_subject_animals;
            case 65:
                return R.string.explanation_subject_music;
            case 66:
                return R.string.explanation_subject_sat;
            case 67:
                return R.string.explanation_subject_critical_reading;
            case 68:
                return R.string.explanation_subject_movies;
            case 69:
                return R.string.explanation_subject_business_studies;
            case 70:
                return R.string.explanation_subject_ap;
            case 71:
                return R.string.explanation_subject_german;
            case 72:
                return R.string.explanation_subject_abstract_algebra;
            case 73:
                return R.string.explanation_subject_complex_variables;
            case 74:
                return R.string.explanation_subject_finite_math;
            case 75:
                return R.string.explanation_subject_analysis;
            case 76:
                return R.string.explanation_subject_education;
            case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                return R.string.explanation_subject_oceanography;
            case 78:
                return R.string.explanation_subject_solving_equations;
            case 79:
                return R.string.explanation_subject_vocational;
            case 80:
                return R.string.explanation_subject_business;
            case 81:
                return R.string.explanation_subject_marketing;
            case 82:
                return R.string.explanation_subject_finance;
            case 83:
                return R.string.explanation_subject_linguistics;
            case 84:
                return R.string.explanation_subject_art;
            case 85:
                return R.string.explanation_subject_film;
            case 86:
                return R.string.explanation_subject_a_level;
            case 87:
                return R.string.explanation_subject_college_prep;
            case 88:
                return R.string.explanation_subject_abnormal_psychology;
            case 89:
                return R.string.explanation_subject_electrical_engineering;
            case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                return R.string.explanation_subject_mechanical_engineering;
            case 91:
                return R.string.explanation_subject_math_foundations;
            case 92:
                return R.string.explanation_subject_materials_science;
            case 93:
                return R.string.explanation_subject_advertising;
            case 94:
                return R.string.explanation_subject_software_engineering;
            case 95:
                return R.string.explanation_subject_civil_law;
            case 96:
                return R.string.explanation_subject_civics;
            case 97:
                return R.string.explanation_subject_administrative_law;
            case 98:
                return R.string.explanation_subject_public_health;
            case 99:
                return R.string.explanation_subject_genetics;
            case 100:
                return R.string.explanation_subject_geology;
            case 101:
                return R.string.explanation_subject_econometrics;
            case 102:
                return R.string.explanation_subject_managerial_economics;
            case 103:
                return R.string.explanation_subject_biotechnology;
            case 104:
                return R.string.explanation_subject_macroeconomics;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
                return R.string.explanation_subject_microbiology;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                return R.string.explanation_subject_molecular_biology;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                return R.string.explanation_subject_comparative_law;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                return R.string.explanation_subject_ethics;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION /* 109 */:
                return R.string.explanation_subject_cardiology;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED /* 110 */:
                return R.string.explanation_subject_cognitive_psychology;
            case 111:
                return R.string.explanation_subject_criminal_law;
            case ContentType.LONG_FORM_ON_DEMAND /* 112 */:
                return R.string.explanation_subject_civil_engineering;
            case ContentType.LIVE /* 113 */:
                return R.string.explanation_subject_computer_architecture;
            case 114:
                return R.string.explanation_subject_biological_psychology;
            case 115:
                return R.string.explanation_subject_ecology;
            case 116:
                return R.string.explanation_subject_cell_biology;
            case 117:
                return R.string.explanation_subject_biological_anthropology;
            case 118:
                return R.string.explanation_subject_neuroscience;
            case 119:
                return R.string.explanation_subject_sports;
            case 120:
                return R.string.explanation_subject_geography_of_north_america;
            case ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND /* 121 */:
                return R.string.explanation_subject_nutrition;
            case ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND /* 122 */:
                return R.string.explanation_subject_microeconomics;
            case ContentType.USER_GENERATED_LIVE /* 123 */:
                return R.string.explanation_subject_scientific_history;
            case 124:
                return R.string.explanation_subject_human_biology;
            case 125:
                return R.string.explanation_subject_inorganic_chemistry;
            case 126:
                return R.string.explanation_subject_life_science;
            case 127:
                return R.string.explanation_subject_international_economics;
            case 128:
                return R.string.explanation_subject_immunology;
            case 129:
                return R.string.explanation_subject_music_theory;
            case 130:
                return R.string.explanation_subject_marine_biology;
            case 131:
                return R.string.explanation_subject_modern_history;
            case 132:
                return R.string.explanation_subject_optometry;
            case 133:
                return R.string.explanation_subject_pathology;
            case 134:
                return R.string.explanation_subject_animal_science;
            case 135:
                return R.string.explanation_subject_psychiatry;
            case 136:
                return R.string.explanation_subject_ancient_history;
        }
    }
}
