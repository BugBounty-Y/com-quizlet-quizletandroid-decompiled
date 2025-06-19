package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Intent;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.io.Serializable;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.t5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3266t5 {
    public static androidx.compose.ui.text.font.A a(int i) {
        return new androidx.compose.ui.text.font.A(i, androidx.compose.ui.text.font.u.f, new androidx.compose.ui.text.font.t(new androidx.compose.ui.text.font.s[0]));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:144:0x02cb  */
    /* JADX WARN: Type inference failed for: r0v10, types: [androidx.compose.runtime.internal.d] */
    /* JADX WARN: Type inference failed for: r20v1 */
    /* JADX WARN: Type inference failed for: r20v2 */
    /* JADX WARN: Type inference failed for: r20v5 */
    /* JADX WARN: Type inference failed for: r3v2, types: [androidx.compose.runtime.l, androidx.compose.runtime.p, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(kotlin.jvm.functions.Function0 r27, androidx.compose.ui.q r28, long r29, final int r31, androidx.compose.foundation.layout.A0 r32, androidx.compose.foundation.layout.InterfaceC0394k r33, androidx.compose.foundation.layout.InterfaceC0388h r34, androidx.compose.foundation.lazy.grid.A r35, androidx.compose.runtime.internal.d r36, androidx.compose.runtime.internal.d r37, final kotlin.jvm.functions.Function2 r38, androidx.compose.runtime.InterfaceC0806l r39, int r40, int r41) {
        /*
            Method dump skipped, instructions count: 891
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3266t5.b(kotlin.jvm.functions.Function0, androidx.compose.ui.q, long, int, androidx.compose.foundation.layout.A0, androidx.compose.foundation.layout.k, androidx.compose.foundation.layout.h, androidx.compose.foundation.lazy.grid.A, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, kotlin.jvm.functions.Function2, androidx.compose.runtime.l, int, int):void");
    }

    public static void c(Intent intent, Integer num, StudyableModelData studyableModelData, Long l, boolean z, String screenName, int i, List list, String str, int i2) {
        if ((i2 & 128) != 0) {
            list = null;
        }
        if ((i2 & 256) != 0) {
            str = null;
        }
        Intrinsics.checkNotNullParameter(intent, "intent");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        intent.putExtra("navigationSource", num);
        intent.putExtra("studyableModelData", studyableModelData);
        intent.putExtra("studyableModelLocalId", l);
        intent.putExtra("selectedOnlyIntent", z);
        intent.putExtra("screen_name_key", screenName);
        intent.putExtra("study_mode_type_key", i);
        if (str == null) {
            str = "";
        }
        intent.putExtra("studyableModelTitle", str);
        if (list != null) {
            intent.putExtra("termsToShowIntent", CollectionsKt.x0(list));
        }
        intent.putExtra("startsInSrsMode", (Serializable) null);
        intent.setAction(studyableModelData.k() + "_" + l + "_" + studyableModelData.getStudyableType().b() + "_" + z);
    }
}
