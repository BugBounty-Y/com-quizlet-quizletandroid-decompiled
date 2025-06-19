package com.quizlet.ui.models.webpage;

import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.quizlet.generated.enums.S0;
import com.quizlet.generated.enums.U0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends f {
    public final S0 b;

    /* JADX WARN: Illegal instructions before constructor call */
    public j(S0 revisionCenterType) {
        U0 u0;
        Intrinsics.checkNotNullParameter(revisionCenterType, "revisionCenterType");
        Intrinsics.checkNotNullParameter(revisionCenterType, "<this>");
        switch (com.quizlet.ui.models.mappers.b.a[revisionCenterType.ordinal()]) {
            case 1:
                u0 = U0.AUSTRALIA_HSC;
                break;
            case 2:
                u0 = U0.AUSTRALIA_VCE;
                break;
            case 3:
                u0 = U0.BRAZIL_ENEM;
                break;
            case 4:
                u0 = U0.BRAZIL_ELL;
                break;
            case 5:
                u0 = U0.ENGLAND_A_LEVELS;
                break;
            case 6:
                u0 = U0.ENGLAND_GCSE;
                break;
            case 7:
                u0 = U0.FLASHCARDS_ELL;
                break;
            case 8:
                u0 = U0.GERMANY_ABITUR;
                break;
            case 9:
                u0 = U0.IELTS;
                break;
            case 10:
                u0 = U0.INDIA_CSE;
                break;
            case 11:
                u0 = U0.INDIA_JEE;
                break;
            case 12:
                u0 = U0.INDIA_NEET;
                break;
            case 13:
                u0 = U0.MEXICO_ELL;
                break;
            case 14:
                u0 = U0.MEXICO_EXANI;
                break;
            case 15:
                u0 = U0.POLAND_MATURA;
                break;
            case 16:
                u0 = U0.SOLUTIONS_BRAZIL;
                break;
            case 17:
                u0 = U0.SOLUTIONS_MEXICO;
                break;
            case 18:
                u0 = U0.TOEFL;
                break;
            case 19:
                u0 = U0.TOEIC;
                break;
            case 20:
                u0 = U0.VIETNAM_ELL;
                break;
            default:
                throw new NoWhenBranchMatchedException();
        }
        super(u0.a());
        this.b = revisionCenterType;
    }

    @Override // com.quizlet.ui.models.webpage.m
    public final com.quizlet.qutils.string.g a() {
        return Y5.d(this.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && this.b == ((j) obj).b;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "RevisionCenterWebPage(revisionCenterType=" + this.b + ")";
    }
}
