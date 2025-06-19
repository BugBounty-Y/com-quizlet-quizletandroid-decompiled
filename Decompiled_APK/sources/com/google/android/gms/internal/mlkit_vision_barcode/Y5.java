package com.google.android.gms.internal.mlkit_vision_barcode;

import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y5 {
    public static final /* synthetic */ int a = 0;

    public static final com.quizlet.qutils.string.g a(com.quizlet.generated.enums.S0 s0, Integer num) {
        Intrinsics.checkNotNullParameter(s0, "<this>");
        if (num == null) {
            return d(s0);
        }
        String strE = e(s0);
        if (num.intValue() == 0) {
            Object[] args = {strE};
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.revision_center_current_day_cta, C4933y.P(args));
        }
        if (num.intValue() == 1) {
            Object[] args2 = {strE};
            Intrinsics.checkNotNullParameter(args2, "args");
            return new com.quizlet.qutils.string.f(R.string.revision_center_next_day_cta, C4933y.P(args2));
        }
        int iIntValue = num.intValue();
        Object[] args3 = {num, strE};
        Intrinsics.checkNotNullParameter(args3, "args");
        return new com.quizlet.qutils.string.d(R.plurals.revision_center_countdown_cta, iIntValue, C4933y.P(args3));
    }

    public static androidx.concurrent.futures.l b(androidx.concurrent.futures.j jVar) {
        androidx.concurrent.futures.i iVar = new androidx.concurrent.futures.i();
        iVar.c = new androidx.concurrent.futures.n();
        androidx.concurrent.futures.l lVar = new androidx.concurrent.futures.l(iVar);
        iVar.b = lVar;
        iVar.a = jVar.getClass();
        try {
            Object objD = jVar.d(iVar);
            if (objD != null) {
                iVar.a = objD;
                return lVar;
            }
        } catch (Exception e) {
            lVar.b.l(e);
        }
        return lVar;
    }

    public static final int c(com.quizlet.generated.enums.S0 s0) {
        Intrinsics.checkNotNullParameter(s0, "<this>");
        switch (com.quizlet.ui.models.mappers.b.a[s0.ordinal()]) {
            case 1:
            case 2:
            case 3:
            case 5:
            case 6:
            case 8:
            case 10:
            case 11:
            case 12:
            case 14:
            case 15:
                return R.drawable.ic_brand_standardized_test;
            case 4:
            case 7:
            case 9:
            case 13:
            case 18:
            case 19:
            case 20:
                return R.drawable.ic_brand_standardized_english;
            case 16:
            case 17:
                throw new IllegalArgumentException();
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final com.quizlet.qutils.string.f d(com.quizlet.generated.enums.S0 s0) {
        Intrinsics.checkNotNullParameter(s0, "<this>");
        switch (com.quizlet.ui.models.mappers.b.a[s0.ordinal()]) {
            case 1:
            case 2:
            case 3:
            case 5:
            case 6:
            case 8:
            case 10:
            case 11:
            case 12:
            case 14:
            case 15:
                Object[] args = {e(s0)};
                Intrinsics.checkNotNullParameter(args, "args");
                return new com.quizlet.qutils.string.f(R.string.revision_center_title, C4933y.P(args));
            case 4:
            case 7:
            case 13:
            case 20:
                Object[] args2 = new Object[0];
                Intrinsics.checkNotNullParameter(args2, "args");
                return new com.quizlet.qutils.string.f(R.string.ell_home_banner, C4933y.P(args2));
            case 9:
            case 18:
            case 19:
                Object[] args3 = {e(s0)};
                Intrinsics.checkNotNullParameter(args3, "args");
                return new com.quizlet.qutils.string.f(R.string.ell_revision_center_exam_title, C4933y.P(args3));
            case 16:
            case 17:
                Object[] args4 = new Object[0];
                Intrinsics.checkNotNullParameter(args4, "args");
                return new com.quizlet.qutils.string.f(R.string.expert_solutions, C4933y.P(args4));
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final String e(com.quizlet.generated.enums.S0 s0) {
        Intrinsics.checkNotNullParameter(s0, "<this>");
        switch (com.quizlet.ui.models.mappers.b.a[s0.ordinal()]) {
            case 1:
                return "HSC";
            case 2:
                return "VCE";
            case 3:
                return "ENEM";
            case 4:
            case 7:
            case 13:
            case 16:
            case 17:
            case 20:
                throw new IllegalArgumentException();
            case 5:
                return "A-Levels";
            case 6:
                return "GCSE";
            case 8:
                return "Abitur";
            case 9:
                return "IELTS®";
            case 10:
                return "CSE Prelims";
            case 11:
                return "JEE Main";
            case 12:
                return "NEET";
            case 14:
                return "Exani II";
            case 15:
                return "Matura";
            case 18:
                return "TOEFL®";
            case 19:
                return "TOEIC®";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
