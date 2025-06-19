package com.quizlet.features.flashcards.settings;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.features.infra.models.flashcards.FlashcardSettings$FlashcardSettingsState;
import com.quizlet.generated.enums.F1;
import com.quizlet.generated.enums.G1;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class j extends w0 implements l {
    public final com.quizlet.billing.register.a b;
    public final com.quizlet.features.flashcards.logging.d c;
    public final com.quizlet.login.authentication.login.a d;
    public final com.quizlet.data.interactor.achievements.f e;
    public final com.google.firebase.crashlytics.internal.settings.b f;
    public final com.quizlet.features.infra.basestudy.manager.f g;
    public final com.quizlet.features.infra.models.flashcards.d h;
    public final long i;
    public final G1 j;
    public final boolean k;
    public final ArrayList l;
    public final s0 m;
    public final d0 n;

    public j(m0 savedStateHandle, com.quizlet.billing.register.a modeSharedPreferencesManager, com.quizlet.features.flashcards.logging.d flashcardsEventLogger, com.quizlet.login.authentication.login.a random, com.quizlet.data.interactor.achievements.f settingsTermUseCase, com.google.firebase.crashlytics.internal.settings.b settingsDefinitionUseCase, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(modeSharedPreferencesManager, "modeSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(flashcardsEventLogger, "flashcardsEventLogger");
        Intrinsics.checkNotNullParameter(random, "random");
        Intrinsics.checkNotNullParameter(settingsTermUseCase, "settingsTermUseCase");
        Intrinsics.checkNotNullParameter(settingsDefinitionUseCase, "settingsDefinitionUseCase");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        this.b = modeSharedPreferencesManager;
        this.c = flashcardsEventLogger;
        this.d = random;
        this.e = settingsTermUseCase;
        this.f = settingsDefinitionUseCase;
        this.g = studyModeManagerFactory.a(savedStateHandle);
        Object objA = savedStateHandle.a("flashcardsModeConfig");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        FlashcardSettings$FlashcardSettingsState state = (FlashcardSettings$FlashcardSettingsState) objA;
        Intrinsics.checkNotNullParameter(state, "state");
        String str = state.a;
        assistantMode.enums.m mVarE = str != null ? AbstractC3106b5.e(str) : null;
        mVarE = mVarE == null ? assistantMode.enums.m.b : mVarE;
        String str2 = state.b;
        assistantMode.enums.m mVarE2 = str2 != null ? AbstractC3106b5.e(str2) : null;
        com.quizlet.features.infra.models.flashcards.d dVar = new com.quizlet.features.infra.models.flashcards.d(mVarE, mVarE2 == null ? assistantMode.enums.m.b : mVarE2, state.c, state.d, state.e, state.f, state.g, state.h, state.i);
        this.h = dVar;
        dVar.b();
        Object objA2 = savedStateHandle.a("flashcardsStudiableId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.i = ((Number) objA2).longValue();
        F1 f1 = G1.Companion;
        Object objA3 = savedStateHandle.a("flashcardsStudiableType");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA3).intValue();
        f1.getClass();
        this.j = F1.a(iIntValue);
        Object objA4 = savedStateHandle.a("flashcardsSelectedCardCount");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.k = ((Number) objA4).intValue() > 0;
        Object objA5 = savedStateHandle.a("flashcardsAvailableCardSides");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Object[] objArr = (Object[]) objA5;
        ArrayList arrayList = new ArrayList(objArr.length);
        for (Object obj : objArr) {
            arrayList.add(AbstractC3106b5.e((String) obj));
        }
        this.l = arrayList;
        com.quizlet.features.infra.models.flashcards.d dVar2 = this.h;
        if (!this.k) {
            dVar2.g = false;
        }
        this.m = e0.c(dVar2);
        this.n = e0.b(0, 0, null, 7);
        E.A(p0.j(this), null, null, new f(this, null), 3);
    }

    public static void A(j jVar, com.quizlet.features.infra.models.flashcards.d dVar, int i) {
        s0 s0Var;
        Object value;
        boolean z = (i & 2) == 0;
        boolean z2 = (i & 4) == 0;
        boolean z3 = (i & 8) == 0;
        jVar.b.e(jVar.i, jVar.j, dVar);
        do {
            s0Var = jVar.m;
            value = s0Var.getValue();
        } while (!s0Var.k(value, dVar));
        E.A(p0.j(jVar), null, null, new i(jVar, dVar, z, z2, z3, null), 3);
    }
}
