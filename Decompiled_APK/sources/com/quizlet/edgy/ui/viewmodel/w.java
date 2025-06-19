package com.quizlet.edgy.ui.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import com.quizlet.data.model.School;
import com.quizlet.edgy.model.Country;
import com.quizlet.edgy.model.State;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class w extends w0 {
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g b;
    public final com.google.firebase.crashlytics.internal.settings.b c;
    public Country d;
    public State e;
    public final s0 f;
    public final s0 g;
    public final s0 h;
    public final d0 i;
    public School j;
    public final androidx.compose.ui.text.font.o k;

    public w(com.quizlet.data.repository.studysetwithcreatorinclass.g edgyUtils, com.google.firebase.crashlytics.internal.settings.b createNewSchoolUseCase) {
        Intrinsics.checkNotNullParameter(edgyUtils, "edgyUtils");
        Intrinsics.checkNotNullParameter(createNewSchoolUseCase, "createNewSchoolUseCase");
        this.b = edgyUtils;
        this.c = createNewSchoolUseCase;
        this.d = new Country(OTCCPAGeolocationConstants.US, "United States");
        kotlin.collections.K k = kotlin.collections.K.a;
        this.f = e0.c(k);
        this.g = e0.c(k);
        this.h = e0.c(Boolean.TRUE);
        this.i = e0.b(0, 0, null, 7);
        this.k = new androidx.compose.ui.text.font.o(C5041z.a, 2);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new u(this, null), 3);
    }
}
