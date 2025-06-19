package com.google.android.gms.measurement.internal;

import android.content.SharedPreferences;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class N {
    public final long a;
    public boolean b;
    public long c;
    public final Object d;
    public final Object e;

    public N(O o, String str, long j) {
        this.e = o;
        com.google.android.gms.common.internal.u.e(str);
        this.d = str;
        this.a = j;
    }

    public long a() {
        if (!this.b) {
            this.b = true;
            this.c = ((O) this.e).X().getLong((String) this.d, this.a);
        }
        return this.c;
    }

    public void b(long j) {
        SharedPreferences.Editor editorEdit = ((O) this.e).X().edit();
        editorEdit.putLong((String) this.d, j);
        editorEdit.apply();
        this.c = j;
    }

    public N(long j, StudyableModelData studyableModelData, boolean z, A1 studyMode) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(studyMode, "studyMode");
        this.a = j;
        this.b = z;
        this.d = studyMode;
        this.c = studyableModelData.k();
        this.e = studyableModelData.getStudyableType();
    }
}
