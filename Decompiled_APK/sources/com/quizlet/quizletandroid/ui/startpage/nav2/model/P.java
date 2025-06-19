package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class P {
    public static final P a;
    public static final P b;
    public static final P c;
    public static final P d;
    public static final P e;
    public static final P f;
    public static final P g;
    public static final P h;
    public static final P i;
    public static final /* synthetic */ P[] j;

    static {
        P p = new P("Folders", 0);
        a = p;
        P p2 = new P("StudySets", 1);
        b = p2;
        P p3 = new P("Classes", 2);
        c = p3;
        P p4 = new P("RecommendedStudySets", 3);
        d = p4;
        P p5 = new P("MyExplanations", 4);
        e = p5;
        P p6 = new P("Achievements", 5);
        f = p6;
        P p7 = new P("MagicNotes", 6);
        g = p7;
        P p8 = new P("BrowseByExam", 7);
        h = p8;
        P p9 = new P("ToDoTasks", 8);
        i = p9;
        P[] pArr = {p, p2, p3, p4, p5, p6, p7, p8, p9};
        j = pArr;
        AbstractC3328d.f(pArr);
    }

    public static P valueOf(String str) {
        return (P) Enum.valueOf(P.class, str);
    }

    public static P[] values() {
        return (P[]) j.clone();
    }

    public final int a(AbstractC3603d6 abstractC3603d6) {
        switch (ordinal()) {
            case 0:
                return R.string.nav2_models_list_title_folders;
            case 1:
                return R.string.nav2_models_list_title_sets;
            case 2:
                return R.string.nav2_models_list_title_classes;
            case 3:
                if (abstractC3603d6 instanceof T) {
                    return R.string.nav2_user_recommended_sets_section_title;
                }
                if (abstractC3603d6 instanceof Q) {
                    return R.string.nav2_set_recommended_sets_section_title;
                }
                if (abstractC3603d6 instanceof C4709e) {
                    return R.string.nav2_course_recommended_sets_section_title;
                }
                if (abstractC3603d6 instanceof N) {
                    return R.string.nav2_school_recommended_sets_section_title;
                }
                Intrinsics.b(abstractC3603d6, C4706b.a);
                return R.string.nav2_recommended_sets_section_title;
            case 4:
                return R.string.nav2_models_list_title_explanations;
            case 5:
                return R.string.nav2_models_list_title_achievements;
            case 6:
                return R.string.magic_notes_detail_label;
            case 7:
                return R.string.empty_home_browse_by_exam_title;
            case 8:
                return R.string.home_logged_in_to_do_section;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
