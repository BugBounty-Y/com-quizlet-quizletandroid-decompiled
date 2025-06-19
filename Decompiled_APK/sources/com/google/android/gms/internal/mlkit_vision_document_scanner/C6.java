package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.data.exceptions.notes.BrokenPdfException;
import com.quizlet.data.exceptions.notes.FileSizeTooLargeException;
import com.quizlet.data.exceptions.notes.FileTypeMismatchException;
import com.quizlet.data.exceptions.notes.InvalidYoutubeUrlException;
import com.quizlet.data.exceptions.notes.MultiFileUploadFilesInvalidException;
import com.quizlet.data.exceptions.notes.NotEnoughCharactersException;
import com.quizlet.data.exceptions.notes.NotesException;
import com.quizlet.data.exceptions.notes.TooManyCharactersException;
import com.quizlet.data.exceptions.notes.UnableToExtractTextException;
import com.quizlet.data.exceptions.notes.UnsupportedFileTypeException;
import com.quizlet.data.exceptions.notes.UploadLimitReachedException;
import com.quizlet.generated.enums.EnumC4477e0;
import com.quizlet.shared.models.api.exceptions.QuizletApiException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class C6 {
    public static final void a(Function1 navigateBack, androidx.compose.ui.n nVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        AbstractC0809m0 abstractC0809m0;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar2;
        androidx.compose.runtime.V v;
        androidx.compose.ui.n nVar3;
        boolean z;
        Object yVar;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(764534972);
        int i3 = (c0814p.h(navigateBack) ? 4 : 2) | i | 48 | (c0814p.f(aVar) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            aVar2 = aVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                nVar2 = nVar;
            }
            c0814p.q();
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, true, c0814p, 438, 0);
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(iVar.p, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = iVar.q;
            c0814p.X(1698094063);
            boolean zH = ((i3 & 14) == 4) | c0814p.h(xVarH);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (zH || objI == v2) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.g(xVarH, null, navigateBack);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m02 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m02);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v2) {
                objI2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.f(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            c0814p.X(1698108021);
            if (xVarH.b()) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o oVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o) interfaceC0773a0G.getValue();
                if (Intrinsics.b(oVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.n.a)) {
                    c0814p.X(1698110730);
                    AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
                    c0814p.p(false);
                    i2 = i3;
                    abstractC0809m0 = abstractC0809m02;
                    aVar2 = aVar;
                    v = v2;
                    z = false;
                    nVar3 = nVar2;
                } else {
                    if (!(oVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m)) {
                        throw com.google.android.gms.measurement.internal.Z.j(1698109131, c0814p, false);
                    }
                    c0814p.X(1101979894);
                    com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o oVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o) interfaceC0773a0G.getValue();
                    Intrinsics.e(oVar2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUiState.Content");
                    com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m) oVar2;
                    c0814p.X(1698121909);
                    boolean z2 = (((i3 & 896) ^ 384) > 256 && c0814p.h(aVar)) || (i3 & 384) == 256;
                    Object objI3 = c0814p.I();
                    if (z2 || objI3 == v2) {
                        v = v2;
                        abstractC0809m0 = abstractC0809m02;
                        z = false;
                        i2 = i3;
                        yVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, aVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/settings/data/LearnSettingsEvent;)V", 0, 2);
                        aVar2 = aVar;
                        c0814p.i0(yVar);
                    } else {
                        i2 = i3;
                        abstractC0809m0 = abstractC0809m02;
                        v = v2;
                        z = false;
                        yVar = objI3;
                        aVar2 = aVar;
                    }
                    c0814p.p(z);
                    nVar3 = nVar2;
                    E6.j(xVarH, mVar, nVar3, (Function1) ((kotlin.reflect.f) yVar), c0814p, 392);
                    c0814p.p(z);
                }
            } else {
                i2 = i3;
                abstractC0809m0 = abstractC0809m02;
                aVar2 = aVar;
                v = v2;
                nVar3 = nVar2;
                z = false;
            }
            c0814p.p(z);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            c0814p.X(1698126817);
            boolean zH2 = c0814p.h(j2) | (((((i2 & 896) ^ 384) <= 256 || !c0814p.h(aVar2)) && (i2 & 384) != 256) ? z : true);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == v) {
                objI4 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.c(j2, aVar2, 0);
                c0814p.i0(objI4);
            }
            c0814p.p(z);
            C0776c.d(j2, (Function1) objI4, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(navigateBack, nVar3, aVar2, i);
        }
    }

    public static final NotesException b(QuizletApiException quizletApiException) {
        Intrinsics.checkNotNullParameter(quizletApiException, "<this>");
        String str = quizletApiException.a;
        return (str == null || !StringsKt.G(str, EnumC4477e0.FILE_SIZE_TOO_LARGE.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.UNSUPPORTED_FILE_TYPE.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.BROKEN_PDF.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.NOT_ENOUGH_CHARACTERS.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.FILE_TYPE_MISMATCH.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.INVALID_YOUTUBE_URL.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.MULTI_FILE_UPLOAD_FILES_INVALID.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.TOO_MANY_CHARACTERS.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.UNABLE_TO_EXTRACT_TEXT.a(), false)) ? (str == null || !StringsKt.G(str, EnumC4477e0.UPLOAD_LIMIT_REACHED.a(), false)) ? new NotesException(quizletApiException.getMessage()) : new UploadLimitReachedException() : new UnableToExtractTextException() : new TooManyCharactersException(null) : new MultiFileUploadFilesInvalidException() : new InvalidYoutubeUrlException() : new FileTypeMismatchException() : new NotEnoughCharactersException() : new BrokenPdfException() : new UnsupportedFileTypeException() : new FileSizeTooLargeException();
    }
}
