package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.os.Build;
import androidx.compose.ui.text.font.C0987a;
import androidx.compose.ui.text.font.C0988b;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.s5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3258s5 {
    /* JADX WARN: Removed duplicated region for block: B:102:0x01d6  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01e6  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0214  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0240  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x024b  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0282  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x028b  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0292 A[PHI: r0
  0x0292: PHI (r0v23 long) = (r0v17 long), (r0v24 long) binds: [B:131:0x0290, B:127:0x0288] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0294  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x02a5  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x02ae  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x02b6 A[PHI: r12
  0x02b6: PHI (r12v36 long) = (r12v31 long), (r12v37 long) binds: [B:141:0x02b4, B:137:0x02ab] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:143:0x02b8  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x02c3  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x02cb A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:151:0x02cd  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x0339  */
    /* JADX WARN: Removed duplicated region for block: B:159:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0163  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0186  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0193  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final androidx.compose.foundation.pager.C0466e r34, final int r35, final androidx.compose.ui.q r36, int r37, final float r38, float r39, androidx.compose.foundation.shape.d r40, long r41, long r43, long r45, long r47, float r49, float r50, float r51, androidx.compose.runtime.InterfaceC0806l r52, final int r53, final int r54, final int r55) {
        /*
            Method dump skipped, instructions count: 850
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3258s5.a(androidx.compose.foundation.pager.e, int, androidx.compose.ui.q, int, float, float, androidx.compose.foundation.shape.d, long, long, long, long, float, float, float, androidx.compose.runtime.l, int, int, int):void");
    }

    public static com.quizlet.features.infra.basestudy.data.models.dataproviders.a b(long j, StudyableModelData studyableModelData, com.quizlet.generated.enums.A1 a1, com.quizlet.infra.legacysyncengine.net.c cVar, com.quizlet.qutils.rx.b bVar, ArrayList arrayList, boolean z) {
        com.quizlet.generated.enums.G1 studyableType = studyableModelData.getStudyableType();
        int i = com.quizlet.features.infra.basestudy.data.models.dataproviders.d.a[studyableType.ordinal()];
        if (i == 1 || i == 2) {
            return new com.quizlet.features.infra.basestudy.data.models.dataproviders.a(j, studyableModelData, a1, cVar, bVar, arrayList, z);
        }
        throw new UnsupportedOperationException("Studyable model type " + studyableType + " not supported");
    }

    public static final androidx.compose.ui.text.font.k c(Context context) {
        return new androidx.compose.ui.text.font.k(new C0987a(context), new C0988b(Build.VERSION.SDK_INT >= 31 ? androidx.compose.ui.text.font.v.a.a(context) : 0));
    }
}
