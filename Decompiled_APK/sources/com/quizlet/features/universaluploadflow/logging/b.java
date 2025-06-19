package com.quizlet.features.universaluploadflow.logging;

import androidx.lifecycle.m0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.data.model.m2;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.notes.logging.e;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final EventLogger a;
    public final m2 b;

    public b(m0 savedStateHandle, EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
        Object objA = savedStateHandle.a("source");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.b = (m2) objA;
    }

    public static void d(b bVar, boolean z, String inputType, Integer num, ArrayList arrayList, int i) {
        String strA;
        if ((i & 4) != 0) {
            num = null;
        }
        Integer num2 = num;
        List list = arrayList;
        if ((i & 8) != 0) {
            list = K.a;
        }
        List fileTypes = list;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        Intrinsics.checkNotNullParameter(fileTypes, "fileTypes");
        UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
        m2 m2Var = bVar.b;
        EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            strA = EnumC4471c0.IMPORT_START.a();
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            strA = "upload_document_started";
        }
        e eVar = new e(z, num2, fileTypes, inputType, 1);
        companion.getClass();
        bVar.a(UniversalUploadFlowEventLog.Companion.a(enumC4503nD, strA, eVar));
    }

    public static void e(final b bVar, String str, final boolean z, Integer num, ArrayList arrayList, final String inputType, int i) {
        String strA;
        if ((i & 1) != 0) {
            str = null;
        }
        if ((i & 4) != 0) {
            num = null;
        }
        List fileTypes = arrayList;
        if ((i & 8) != 0) {
            fileTypes = K.a;
        }
        bVar.getClass();
        Intrinsics.checkNotNullParameter(fileTypes, "fileTypes");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
        m2 m2Var = bVar.b;
        EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            strA = EnumC4471c0.IMPORT_SUCCESS.a();
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            strA = "upload_document_succeeded";
        }
        String str2 = strA;
        final List list = fileTypes;
        final Integer num2 = num;
        final String str3 = str;
        Function1 function1 = new Function1() { // from class: com.quizlet.features.universaluploadflow.logging.a
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UniversalUploadFlowEventLog.Payload createEvent = (UniversalUploadFlowEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                m2 m2Var2 = this.a.b;
                m2 m2Var3 = m2.c;
                String str4 = str3;
                if (m2Var2 == m2Var3) {
                    createEvent.setQuestionBankId(str4);
                } else {
                    createEvent.setNoteId(str4);
                }
                createEvent.setVisible(Boolean.valueOf(z));
                Integer num3 = num2;
                if (num3 != null) {
                    createEvent.setCharCount(Integer.valueOf(num3.intValue()));
                }
                createEvent.setFileTypes(list);
                createEvent.setInputType(inputType);
                return Unit.a;
            }
        };
        companion.getClass();
        bVar.a(UniversalUploadFlowEventLog.Companion.a(enumC4503nD, str2, function1));
    }

    public final void a(UniversalUploadFlowEventLog universalUploadFlowEventLog) {
        this.a.l(universalUploadFlowEventLog);
    }

    public final void b() {
        m2 m2Var = this.b;
        try {
            UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
            EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
            Intrinsics.checkNotNullParameter(m2Var, "<this>");
            int iOrdinal = m2Var.ordinal();
            if (iOrdinal == 0 || iOrdinal == 1) {
                throw new IllegalStateException("Generate button clicked is not applicable for this source");
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, "generate_button_clicked"));
        } catch (IllegalStateException unused) {
        }
    }

    public final void c() {
        String strA;
        UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
        m2 m2Var = this.b;
        EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            strA = EnumC4471c0.IMPORT_FAILURE.a();
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            strA = "upload_document_failed";
        }
        a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, strA));
    }

    public final void f() {
        m2 m2Var = this.b;
        try {
            UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
            EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
            Intrinsics.checkNotNullParameter(m2Var, "<this>");
            int iOrdinal = m2Var.ordinal();
            if (iOrdinal == 0 || iOrdinal == 1) {
                throw new IllegalStateException("Upload loading screen seen is not applicable for this source");
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, "upload_loading_screen_seen"));
        } catch (IllegalStateException unused) {
        }
    }

    public final void g() {
        m2 m2Var = this.b;
        try {
            UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
            EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
            Intrinsics.checkNotNullParameter(m2Var, "<this>");
            int iOrdinal = m2Var.ordinal();
            if (iOrdinal == 0 || iOrdinal == 1) {
                throw new IllegalStateException("Upload page error screen back button clicked is not applicable for this source");
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, "upload_page_error_screen_back_button_clicked"));
        } catch (IllegalStateException unused) {
        }
    }

    public final void h() {
        m2 m2Var = this.b;
        try {
            UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
            EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
            Intrinsics.checkNotNullParameter(m2Var, "<this>");
            int iOrdinal = m2Var.ordinal();
            if (iOrdinal == 0 || iOrdinal == 1) {
                throw new IllegalStateException("Upload page error screen seen is not applicable for this source");
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            a(UniversalUploadFlowEventLog.Companion.b(companion, enumC4503nD, "upload_page_error_screen_seen"));
        } catch (IllegalStateException unused) {
        }
    }
}
