package com.quizlet.library.paging;

import androidx.paging.P0;
import androidx.paging.S0;
import androidx.paging.T0;
import com.quizlet.data.interactor.notes.f;
import com.quizlet.quizletandroid.k;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends S0 {
    public final f b;
    public final k c;
    public final int d;
    public final long e;
    public final LinkedHashSet f;

    public b(f getAllStudyNotesUseCase, k getBucketedStudyNotesBySectionsUseCase, long j) {
        Intrinsics.checkNotNullParameter(getAllStudyNotesUseCase, "getAllStudyNotesUseCase");
        Intrinsics.checkNotNullParameter(getBucketedStudyNotesBySectionsUseCase, "getBucketedStudyNotesBySectionsUseCase");
        this.b = getAllStudyNotesUseCase;
        this.c = getBucketedStudyNotesBySectionsUseCase;
        this.d = 20;
        this.e = j;
        this.f = new LinkedHashSet();
    }

    @Override // androidx.paging.S0
    public final Integer a(T0 state) {
        Integer num;
        Integer num2;
        Intrinsics.checkNotNullParameter(state, "state");
        Integer num3 = state.b;
        if (num3 == null) {
            return null;
        }
        int iIntValue = num3.intValue();
        P0 p0A = state.a(iIntValue);
        if (p0A != null && (num2 = p0A.b) != null) {
            return Integer.valueOf(num2.intValue() + 1);
        }
        P0 p0A2 = state.a(iIntValue);
        if (p0A2 == null || (num = p0A2.c) == null) {
            return null;
        }
        return Integer.valueOf(num.intValue() - 1);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.paging.S0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(androidx.paging.N0 r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.library.paging.b.c(androidx.paging.N0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
