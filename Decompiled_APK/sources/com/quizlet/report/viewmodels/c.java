package com.quizlet.report.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.generated.enums.Q0;
import com.quizlet.report.data.k;
import com.quizlet.report.data.m;
import com.quizlet.report.data.n;
import com.quizlet.report.data.o;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 implements a {
    public final com.quizlet.data.interactor.course.a b;
    public final int c;
    public final String d;
    public Q0 e;
    public final s0 f;
    public final d0 g;
    public n h;
    public Integer i;

    public c(m0 savedStateHandle, com.quizlet.data.interactor.course.a submitReportUseCase) {
        n nVar;
        n nVar2;
        boolean z;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(submitReportUseCase, "submitReportUseCase");
        this.b = submitReportUseCase;
        Object objA = savedStateHandle.a(DBImageRefFields.Names.MODEL_TYPE);
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA).intValue();
        this.c = iIntValue;
        this.d = (String) savedStateHandle.a(DBImageRefFields.Names.MODEL_ID);
        if (iIntValue == 20 || iIntValue == 26) {
            nVar = k.a;
        } else {
            if (iIntValue != 28 && iIntValue != 30) {
                throw new IllegalArgumentException("Model type: " + this + " not implemented yet. Do it.");
            }
            nVar = m.a;
        }
        if (iIntValue == 20 || iIntValue == 26 || iIntValue == 28) {
            nVar2 = nVar;
            z = true;
        } else {
            nVar2 = nVar;
            z = false;
        }
        this.f = e0.c(new o(nVar2, null, z, false, false, false, null));
        this.g = e0.b(0, 1, null, 5);
    }
}
