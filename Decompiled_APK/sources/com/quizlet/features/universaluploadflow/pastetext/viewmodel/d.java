package com.quizlet.features.universaluploadflow.pastetext.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.appset.e;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.data.model.m2;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.universaluploadflow.pastetext.data.f;
import com.quizlet.features.universaluploadflow.pastetext.data.g;
import com.quizlet.features.universaluploadflow.pastetext.data.h;
import com.quizlet.features.universaluploadflow.pastetext.data.i;
import com.quizlet.features.universaluploadflow.pastetext.data.m;
import com.quizlet.features.universaluploadflow.pastetext.data.o;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class d extends w0 implements a {
    public final e b;
    public final com.quizlet.features.universaluploadflow.logging.b c;
    public final s0 d;
    public final d0 e;
    public final m2 f;
    public final boolean g;
    public final C4203d h;

    public d(m0 savedStateHandle, e uploadContentUseCase, com.quizlet.features.universaluploadflow.logging.b eventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(uploadContentUseCase, "uploadContentUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = uploadContentUseCase;
        this.c = eventLogger;
        Intrinsics.checkNotNullParameter("", "text");
        this.d = e0.c(new m());
        this.e = e0.b(0, 1, null, 5);
        Object objA = savedStateHandle.a("source");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.f = (m2) objA;
        Boolean bool = (Boolean) savedStateHandle.a("isPrivacySettingsPublic");
        this.g = bool != null ? bool.booleanValue() : true;
        this.h = new C4203d(this);
    }

    public final void A(g event) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.features.universaluploadflow.pastetext.data.a.a);
        h hVar = h.a;
        d0 d0Var = this.e;
        if (zB) {
            d0Var.h(hVar);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.universaluploadflow.pastetext.data.b.a)) {
            d0Var.h(i.a);
            return;
        }
        boolean zB2 = Intrinsics.b(event, com.quizlet.features.universaluploadflow.pastetext.data.c.a);
        com.quizlet.features.universaluploadflow.logging.b bVar = this.c;
        if (zB2) {
            bVar.g();
            d0Var.h(hVar);
            return;
        }
        try {
            if (event instanceof f) {
                m2 m2Var = bVar.b;
                UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
                EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
                Intrinsics.checkNotNullParameter(m2Var, "<this>");
                int iOrdinal = m2Var.ordinal();
                if (iOrdinal == 0 || iOrdinal == 1) {
                    throw new IllegalStateException("Upload page text typed is not applicable for this source");
                }
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                bVar.a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, "upload_page_text_typed"));
                return;
            }
            if (event instanceof com.quizlet.features.universaluploadflow.pastetext.data.e) {
                m2 m2Var2 = bVar.b;
                UniversalUploadFlowEventLog.Companion companion2 = UniversalUploadFlowEventLog.b;
                EnumC4503n enumC4503nD2 = AbstractC3442d4.d(m2Var2);
                Intrinsics.checkNotNullParameter(m2Var2, "<this>");
                int iOrdinal2 = m2Var2.ordinal();
                if (iOrdinal2 == 0 || iOrdinal2 == 1) {
                    throw new IllegalStateException("Generate button enabled is not applicable for this source");
                }
                if (iOrdinal2 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                bVar.a(UniversalUploadFlowEventLog.Companion.b(companion2, enumC4503nD2, "generate_button_enabled"));
                return;
            }
            if (!(event instanceof com.quizlet.features.universaluploadflow.pastetext.data.d)) {
                throw new NoWhenBranchMatchedException();
            }
            String str = ((com.quizlet.features.universaluploadflow.pastetext.data.d) event).a;
            bVar.b();
            bVar.f();
            int length = str.length();
            com.quizlet.features.universaluploadflow.logging.b.d(this.c, this.g, EnumC4483g0.TEXT.a(), Integer.valueOf(length), null, 8);
            do {
                s0Var = this.d;
                value = s0Var.getValue();
            } while (!s0Var.k(value, new o(this.f)));
            E.A(p0.j(this), this.h, null, new c(str, this, null), 2);
        } catch (IllegalStateException unused) {
        }
    }
}
