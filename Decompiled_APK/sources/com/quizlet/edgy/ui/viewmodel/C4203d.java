package com.quizlet.edgy.ui.viewmodel;

import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.exceptions.classcreation.ClassCreationMissingTitleException;
import com.quizlet.data.exceptions.feed.FeedNoInternetException;
import com.quizlet.data.exceptions.library.LibraryClassesException;
import com.quizlet.data.exceptions.library.LibraryFoldersException;
import com.quizlet.data.exceptions.library.LibraryStudySetsException;
import com.quizlet.data.exceptions.notes.BrokenPdfException;
import com.quizlet.data.exceptions.notes.FileSizeTooLargeException;
import com.quizlet.data.exceptions.notes.FileTypeMismatchException;
import com.quizlet.data.exceptions.notes.InvalidYoutubeUrlException;
import com.quizlet.data.exceptions.notes.ModerationException;
import com.quizlet.data.exceptions.notes.MultiFileUploadFilesInvalidException;
import com.quizlet.data.exceptions.notes.NoInternetStudyNotesException;
import com.quizlet.data.exceptions.notes.NotEnoughCharactersException;
import com.quizlet.data.exceptions.notes.NotesException;
import com.quizlet.data.exceptions.notes.TooManyCharactersException;
import com.quizlet.data.exceptions.notes.UnableToExtractTextException;
import com.quizlet.data.exceptions.notes.UnsupportedFileTypeException;
import com.quizlet.data.exceptions.notes.UploadLimitReachedException;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowFileSizeTooLargeException;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowLoadContentException;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowNoInternetException;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowPaywallException;
import com.quizlet.data.model.m2;
import com.quizlet.data.repository.course.exceptions.CourseInstancesException;
import com.quizlet.data.repository.course.exceptions.CourseNotFoundException;
import com.quizlet.data.repository.course.exceptions.CreateDuplicatedCourseException;
import com.quizlet.data.repository.course.exceptions.CreateNewCourseException;
import com.quizlet.data.repository.course.exceptions.CreateNewCourseMembershipException;
import com.quizlet.data.repository.course.exceptions.DeleteCourseMembershipException;
import com.quizlet.data.repository.school.exceptions.CreateNewSchoolMembershipException;
import com.quizlet.data.repository.school.exceptions.DeleteSchoolMembershipException;
import com.quizlet.data.repository.school.exceptions.SchoolMembershipException;
import com.quizlet.data.repository.school.exceptions.SchoolNotFoundException;
import com.quizlet.data.repository.search.exception.SearchTypeAheadException;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.setpage.screenstates.C4424d;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.universaluploadflow.data.C4452a;
import com.quizlet.features.universaluploadflow.data.C4453b;
import com.quizlet.features.universaluploadflow.data.C4454c;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.generated.enums.EnumC4477e0;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.c0;
import com.quizlet.quizletandroid.ui.library.data.C4651e;
import com.quizlet.quizletandroid.ui.library.data.C4654h;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

/* renamed from: com.quizlet.edgy.ui.viewmodel.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4203d extends kotlin.coroutines.a implements kotlinx.coroutines.A {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Object b;

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(C4204e c4204e) {
        C5041z c5041z = C5041z.a;
        this.b = c4204e;
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) throws Throwable {
        Object value;
        Object value2;
        Object value3;
        s0 s0Var;
        Object value4;
        s0 s0Var2;
        Object value5;
        s0 s0Var3;
        Object value6;
        s0 s0Var4;
        Object value7;
        s0 s0Var5;
        Object value8;
        s0 s0Var6;
        Object value9;
        s0 s0Var7;
        Object value10;
        s0 s0Var8;
        Object value11;
        s0 s0Var9;
        Object value12;
        s0 s0Var10;
        Object value13;
        s0 s0Var11;
        Object value14;
        s0 s0Var12;
        Object value15;
        s0 s0Var13;
        Object value16;
        s0 s0Var14;
        Object value17;
        s0 s0Var15;
        Object value18;
        Object value19;
        Object value20;
        String strA;
        Object value21;
        Object value22;
        Object value23;
        Object value24;
        s0 s0Var16;
        Object value25;
        Object value26;
        int i = 1;
        int i2 = 0;
        String strA2 = null;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                if ((th instanceof CreateNewCourseException) || !(th instanceof CreateDuplicatedCourseException)) {
                    return;
                }
                CreateDuplicatedCourseException createDuplicatedCourseException = (CreateDuplicatedCourseException) th;
                String str = createDuplicatedCourseException.a;
                C4204e c4204e = (C4204e) obj;
                c4204e.getClass();
                kotlinx.coroutines.E.A(p0.j(c4204e), c4204e.f, null, new C4201b(c4204e, str, createDuplicatedCourseException.b, null), 2);
                return;
            case 1:
                M m = (M) obj;
                if (th instanceof CourseInstancesException) {
                    m.F(true);
                    return;
                }
                if (th instanceof SchoolMembershipException) {
                    m.F(true);
                    return;
                }
                if (th instanceof SchoolNotFoundException) {
                    s0 s0Var17 = m.p;
                    do {
                        value2 = s0Var17.getValue();
                    } while (!s0Var17.k(value2, C4209j.a));
                    return;
                }
                if (th instanceof CourseNotFoundException) {
                    s0 s0Var18 = m.p;
                    do {
                        value = s0Var18.getValue();
                    } while (!s0Var18.k(value, C4208i.a));
                    return;
                }
                if (th instanceof DeleteSchoolMembershipException) {
                    com.quizlet.edgy.ui.recyclerview.adapter.i iVar = m.k;
                    if (iVar != null) {
                        m.E(iVar, false);
                        return;
                    }
                    return;
                }
                if (th instanceof CreateNewSchoolMembershipException) {
                    m.F(true);
                    return;
                }
                if (!(th instanceof CreateNewCourseMembershipException)) {
                    if (th instanceof DeleteCourseMembershipException) {
                        m.D();
                        return;
                    }
                    return;
                } else {
                    com.quizlet.edgy.ui.recyclerview.adapter.i iVar2 = m.k;
                    if (iVar2 != null) {
                        m.E(iVar2, false);
                        return;
                    }
                    return;
                }
            case 2:
                s0 s0Var19 = ((com.quizlet.features.achievements.viewmodel.b) obj).g;
                do {
                    value3 = s0Var19.getValue();
                } while (!s0Var19.k(value3, com.quizlet.features.achievements.data.g.a));
                return;
            case 3:
                if (th instanceof FeedNoInternetException) {
                    com.quizlet.features.home.viewmodel.c cVar = (com.quizlet.features.home.viewmodel.c) obj;
                    cVar.getClass();
                    kotlinx.coroutines.E.A(p0.j(cVar), null, null, new com.quizlet.features.home.viewmodel.a(cVar, null), 3);
                    return;
                }
                return;
            case 4:
                ((com.quizlet.features.infra.folder.menu.viewmodel.m) obj).h.h(new com.quizlet.features.infra.folder.menu.data.n(th));
                return;
            case 5:
                com.quizlet.features.notes.upload.viewmodels.c cVar2 = (com.quizlet.features.notes.upload.viewmodels.c) obj;
                com.quizlet.features.notes.logging.f fVar = cVar2.f;
                fVar.getClass();
                NotesEventLog.Companion companion = NotesEventLog.b;
                String strA3 = EnumC4471c0.IMPORT_FAILURE.a();
                EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.b;
                fVar.a(NotesEventLog.Companion.b(companion, enumC4503n, strA3));
                if (th instanceof NotesException) {
                    NotesException notesException = (NotesException) th;
                    Intrinsics.checkNotNullParameter(notesException, "<this>");
                    if (notesException instanceof FileSizeTooLargeException) {
                        strA2 = EnumC4477e0.FILE_SIZE_TOO_LARGE.a();
                    } else if (notesException instanceof UnsupportedFileTypeException) {
                        strA2 = EnumC4477e0.UNSUPPORTED_FILE_TYPE.a();
                    } else if (notesException instanceof BrokenPdfException) {
                        strA2 = EnumC4477e0.BROKEN_PDF.a();
                    } else if (notesException instanceof NotEnoughCharactersException) {
                        strA2 = EnumC4477e0.NOT_ENOUGH_CHARACTERS.a();
                    } else if (notesException instanceof FileTypeMismatchException) {
                        strA2 = EnumC4477e0.FILE_TYPE_MISMATCH.a();
                    } else if (notesException instanceof InvalidYoutubeUrlException) {
                        strA2 = EnumC4477e0.INVALID_YOUTUBE_URL.a();
                    } else if (notesException instanceof MultiFileUploadFilesInvalidException) {
                        strA2 = EnumC4477e0.MULTI_FILE_UPLOAD_FILES_INVALID.a();
                    } else if (notesException instanceof TooManyCharactersException) {
                        strA2 = EnumC4477e0.TOO_MANY_CHARACTERS.a();
                    } else if (notesException instanceof UnableToExtractTextException) {
                        strA2 = EnumC4477e0.UNABLE_TO_EXTRACT_TEXT.a();
                    } else if (notesException instanceof UploadLimitReachedException) {
                        strA2 = EnumC4477e0.UPLOAD_LIMIT_REACHED.a();
                    }
                    cVar2.G(strA2);
                }
                timber.log.c.a.p(th);
                if (th instanceof NoInternetStudyNotesException) {
                    X xE = cVar2.E();
                    do {
                        s0Var13 = (s0) xE;
                        value16 = s0Var13.getValue();
                    } while (!s0Var13.k(value16, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.p.a)));
                    return;
                }
                if (th instanceof ModerationException) {
                    X xE2 = cVar2.E();
                    do {
                        s0Var12 = (s0) xE2;
                        value15 = s0Var12.getValue();
                    } while (!s0Var12.k(value15, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.n.a)));
                    return;
                }
                if (th instanceof FileSizeTooLargeException) {
                    com.quizlet.features.notes.logging.f fVar2 = cVar2.f;
                    fVar2.getClass();
                    fVar2.a(NotesEventLog.Companion.a(enumC4503n, EnumC4471c0.COMPUTER_FILE_DETECTED_SIZE_TOO_LARGE.a(), new Z(23)));
                    X xE3 = cVar2.E();
                    do {
                        s0Var11 = (s0) xE3;
                        value14 = s0Var11.getValue();
                    } while (!s0Var11.k(value14, new com.quizlet.features.notes.upload.states.g(new com.quizlet.features.notes.data.j(cVar2.o / 1024))));
                    return;
                }
                if (th instanceof UnsupportedFileTypeException) {
                    X xE4 = cVar2.E();
                    do {
                        s0Var10 = (s0) xE4;
                        value13 = s0Var10.getValue();
                    } while (!s0Var10.k(value13, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.v.a)));
                    return;
                }
                if (th instanceof BrokenPdfException) {
                    X xE5 = cVar2.E();
                    do {
                        s0Var9 = (s0) xE5;
                        value12 = s0Var9.getValue();
                    } while (!s0Var9.k(value12, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.h.a)));
                    return;
                }
                if (th instanceof NotEnoughCharactersException) {
                    cVar2.H();
                    X xE6 = cVar2.E();
                    do {
                        s0Var8 = (s0) xE6;
                        value11 = s0Var8.getValue();
                    } while (!s0Var8.k(value11, new com.quizlet.features.notes.upload.states.g(new com.quizlet.features.notes.data.r(cVar2.n))));
                    return;
                }
                if (th instanceof FileTypeMismatchException) {
                    X xE7 = cVar2.E();
                    do {
                        s0Var7 = (s0) xE7;
                        value10 = s0Var7.getValue();
                    } while (!s0Var7.k(value10, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.k.a)));
                    return;
                }
                if (th instanceof InvalidYoutubeUrlException) {
                    X xE8 = cVar2.E();
                    do {
                        s0Var6 = (s0) xE8;
                        value9 = s0Var6.getValue();
                    } while (!s0Var6.k(value9, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.l.a)));
                    return;
                }
                if (th instanceof MultiFileUploadFilesInvalidException) {
                    X xE9 = cVar2.E();
                    do {
                        s0Var5 = (s0) xE9;
                        value8 = s0Var5.getValue();
                    } while (!s0Var5.k(value8, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.o.a)));
                    return;
                }
                if (th instanceof TooManyCharactersException) {
                    cVar2.I();
                    X xE10 = cVar2.E();
                    do {
                        s0Var4 = (s0) xE10;
                        value7 = s0Var4.getValue();
                    } while (!s0Var4.k(value7, new com.quizlet.features.notes.upload.states.g(new com.quizlet.features.notes.data.t(cVar2.m))));
                    return;
                }
                if (th instanceof UnableToExtractTextException) {
                    X xE11 = cVar2.E();
                    do {
                        s0Var3 = (s0) xE11;
                        value6 = s0Var3.getValue();
                    } while (!s0Var3.k(value6, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.u.a)));
                    return;
                }
                if (th instanceof UploadLimitReachedException) {
                    X xE12 = cVar2.E();
                    do {
                        s0Var2 = (s0) xE12;
                        value5 = s0Var2.getValue();
                    } while (!s0Var2.k(value5, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.w.a)));
                    return;
                }
                X xE13 = cVar2.E();
                do {
                    s0Var = (s0) xE13;
                    value4 = s0Var.getValue();
                } while (!s0Var.k(value4, new com.quizlet.features.notes.upload.states.g(com.quizlet.features.notes.data.g.a)));
                return;
            case 6:
                com.quizlet.features.practicetest.results.viewmodel.h hVar = (com.quizlet.features.practicetest.results.viewmodel.h) obj;
                kotlinx.coroutines.E.A(p0.j(hVar), null, null, new com.quizlet.features.practicetest.results.viewmodel.f(th, hVar, null), 3);
                return;
            case 7:
                com.quizlet.features.practicetest.takingtest.viewmodel.l lVar = (com.quizlet.features.practicetest.takingtest.viewmodel.l) obj;
                kotlinx.coroutines.E.A(p0.j(lVar), null, null, new com.quizlet.features.practicetest.takingtest.viewmodel.h(th, lVar, null), 3);
                return;
            case 8:
                timber.log.c.a.p(th);
                s0 s0Var20 = ((com.quizlet.features.questiontypes.selfassessment.h) obj).j;
                Boolean bool = Boolean.FALSE;
                s0Var20.getClass();
                s0Var20.m(null, bool);
                return;
            case 9:
                P p = (P) obj;
                p.d1.j(com.quizlet.features.setpage.screenstates.p.a);
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                p.j1.j(new C4424d(new com.quizlet.qutils.string.f(R.string.client_error_net_exception, C4933y.P(args)), false));
                timber.log.c.a.p(th);
                return;
            case 10:
                ((com.quizlet.features.settings.viewmodels.k) obj).d.h(Boolean.TRUE);
                return;
            case 11:
                com.quizlet.features.universaluploadflow.flashcards.viewmodel.e eVar = (com.quizlet.features.universaluploadflow.flashcards.viewmodel.e) obj;
                if (th instanceof UniversalUploadFlowLoadContentException) {
                    do {
                        s0Var15 = eVar.g;
                        value18 = s0Var15.getValue();
                    } while (!s0Var15.k(value18, new com.quizlet.features.universaluploadflow.flashcards.data.p(false, 15, null)));
                    return;
                }
                if (th instanceof UniversalUploadFlowPaywallException) {
                    eVar.h.h(com.quizlet.features.universaluploadflow.flashcards.data.l.a);
                    return;
                }
                com.quizlet.features.universaluploadflow.flashcards.data.p pVar = eVar.k;
                if (pVar != null) {
                    do {
                        s0Var14 = eVar.g;
                        value17 = s0Var14.getValue();
                    } while (!s0Var14.k(value17, pVar));
                }
                eVar.h.h(com.quizlet.features.universaluploadflow.flashcards.data.k.a);
                return;
            case 12:
                com.quizlet.features.universaluploadflow.pastetext.viewmodel.d dVar = (com.quizlet.features.universaluploadflow.pastetext.viewmodel.d) obj;
                dVar.c.c();
                boolean z = th instanceof UniversalUploadFlowNoInternetException;
                s0 s0Var21 = dVar.d;
                com.quizlet.features.universaluploadflow.logging.b bVar = dVar.c;
                if (z) {
                    C4454c c4454c = new C4454c(new com.quizlet.features.universaluploadflow.pastetext.viewmodel.b(dVar, i2));
                    bVar.h();
                    do {
                        value20 = s0Var21.getValue();
                    } while (!s0Var21.k(value20, new com.quizlet.features.universaluploadflow.pastetext.data.n(c4454c)));
                    return;
                }
                if (th instanceof UniversalUploadFlowPaywallException) {
                    dVar.e.h(com.quizlet.features.universaluploadflow.pastetext.data.j.a);
                    return;
                }
                C4453b c4453b = new C4453b(dVar.f, new com.quizlet.features.universaluploadflow.pastetext.viewmodel.b(dVar, i));
                bVar.h();
                do {
                    value19 = s0Var21.getValue();
                } while (!s0Var21.k(value19, new com.quizlet.features.universaluploadflow.pastetext.data.n(c4453b)));
                return;
            case 13:
                com.quizlet.features.universaluploadflow.viewmodel.g gVar = (com.quizlet.features.universaluploadflow.viewmodel.g) obj;
                gVar.e.c();
                if (!(th instanceof UniversalUploadFlowFileSizeTooLargeException)) {
                    if (th instanceof UniversalUploadFlowNoInternetException) {
                        com.quizlet.features.universaluploadflow.viewmodel.g.B(gVar, new C4454c(new com.quizlet.features.universaluploadflow.viewmodel.c(gVar, 1)));
                        return;
                    } else if (th instanceof UniversalUploadFlowPaywallException) {
                        gVar.k.h(com.quizlet.features.universaluploadflow.data.A.a);
                        return;
                    } else {
                        com.quizlet.features.universaluploadflow.viewmodel.g.B(gVar, new C4453b(gVar.i, new com.quizlet.features.universaluploadflow.viewmodel.c(gVar, 2)));
                        return;
                    }
                }
                int i3 = ((UniversalUploadFlowFileSizeTooLargeException) th).a;
                String error = "Files cannot exceed " + i3 + " MB";
                com.quizlet.features.universaluploadflow.logging.b bVar2 = gVar.e;
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(error, "error");
                UniversalUploadFlowEventLog.Companion companion2 = UniversalUploadFlowEventLog.b;
                m2 m2Var = bVar2.b;
                EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
                Intrinsics.checkNotNullParameter(m2Var, "<this>");
                int iOrdinal = m2Var.ordinal();
                if (iOrdinal == 0 || iOrdinal == 1) {
                    strA = EnumC4471c0.COMPUTER_FILE_ERROR.a();
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    strA = "select_file_error";
                }
                com.quizlet.features.notes.logging.c cVar3 = new com.quizlet.features.notes.logging.c(error, 27);
                companion2.getClass();
                bVar2.a(UniversalUploadFlowEventLog.Companion.a(enumC4503nD, strA, cVar3));
                com.quizlet.features.universaluploadflow.viewmodel.g.B(gVar, new C4452a(i3, new com.quizlet.features.universaluploadflow.viewmodel.c(gVar, 0)));
                return;
            case 14:
                com.quizlet.learn.viewmodel.G.C((com.quizlet.learn.viewmodel.G) obj, th);
                return;
            case 15:
                if (!(th instanceof PracticeTestsException)) {
                    timber.log.c.a.e(th);
                    return;
                }
                com.quizlet.library.viewmodels.l lVar2 = (com.quizlet.library.viewmodels.l) obj;
                lVar2.getClass();
                kotlinx.coroutines.E.A(p0.j(lVar2), null, null, new com.quizlet.library.viewmodels.k(lVar2, null), 3);
                return;
            case 16:
                com.quizlet.library.viewmodels.s sVar = (com.quizlet.library.viewmodels.s) obj;
                sVar.getClass();
                kotlinx.coroutines.E.A(p0.j(sVar), null, null, new com.quizlet.library.viewmodels.r(sVar, null), 3);
                return;
            case 17:
                if (!(th instanceof ClassCreationMissingTitleException)) {
                    timber.log.c.a.p(th);
                    Unit unit = Unit.a;
                    throw th;
                }
                s0 s0Var22 = ((com.quizlet.quizletandroid.ui.classcreation.i) obj).f;
                do {
                    value21 = s0Var22.getValue();
                    com.quizlet.quizletandroid.ui.classcreation.data.b errorType = com.quizlet.quizletandroid.ui.classcreation.data.b.a;
                    Intrinsics.checkNotNullParameter(errorType, "errorType");
                } while (!s0Var22.k(value21, new com.quizlet.quizletandroid.ui.classcreation.data.h()));
                return;
            case 18:
                timber.log.a aVar = timber.log.c.a;
                aVar.b(th);
                c0 c0Var = (c0) obj;
                if (th instanceof LibraryStudySetsException) {
                    s0 s0Var23 = c0Var.t;
                    do {
                        value24 = s0Var23.getValue();
                    } while (!s0Var23.k(value24, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value24, null, null, com.quizlet.quizletandroid.ui.library.data.H.a, null, null, false, false, false, 251)));
                    return;
                } else if (th instanceof LibraryFoldersException) {
                    s0 s0Var24 = c0Var.t;
                    do {
                        value23 = s0Var24.getValue();
                    } while (!s0Var24.k(value23, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value23, null, null, null, C4654h.a, null, false, false, false, 247)));
                    return;
                } else {
                    if (!(th instanceof LibraryClassesException)) {
                        aVar.p(th);
                        return;
                    }
                    s0 s0Var25 = c0Var.t;
                    do {
                        value22 = s0Var25.getValue();
                    } while (!s0Var25.k(value22, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value22, null, null, null, null, C4651e.a, false, false, false, 239)));
                    return;
                }
            case 19:
                if (!(th instanceof SearchTypeAheadException)) {
                    timber.log.c.a.o("Coroutine exception caught: " + th, new Object[0]);
                    return;
                }
                com.quizlet.search.viewmodels.p pVar2 = (com.quizlet.search.viewmodels.p) obj;
                y0 y0Var = pVar2.m;
                if (y0Var == null || y0Var.isCancelled()) {
                    return;
                }
                do {
                    s0Var16 = pVar2.i;
                    value25 = s0Var16.getValue();
                } while (!s0Var16.k(value25, com.quizlet.search.data.g.a));
                return;
            case 20:
                s0 s0Var26 = ((com.quizlet.search.viewmodels.r) obj).e;
                do {
                    value26 = s0Var26.getValue();
                } while (!s0Var26.k(value26, new com.quizlet.search.data.blended.h(kotlin.collections.A.b(com.quizlet.ui.models.search.b.a))));
                timber.log.c.a.b(th);
                return;
            default:
                timber.log.c.a.h(th);
                com.quizlet.search.viewmodels.M m2 = (com.quizlet.search.viewmodels.M) obj;
                kotlinx.coroutines.E.A(p0.j(m2), null, null, new com.quizlet.search.viewmodels.H(m2, null), 3);
                return;
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(M m) {
        C5041z c5041z = C5041z.a;
        this.b = m;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.achievements.viewmodel.b bVar) {
        C5041z c5041z = C5041z.a;
        this.b = bVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.home.viewmodel.c cVar) {
        C5041z c5041z = C5041z.a;
        this.b = cVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.infra.folder.menu.viewmodel.m mVar) {
        C5041z c5041z = C5041z.a;
        this.b = mVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.notes.upload.viewmodels.c cVar) {
        C5041z c5041z = C5041z.a;
        this.b = cVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.practicetest.results.viewmodel.h hVar) {
        C5041z c5041z = C5041z.a;
        this.b = hVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.practicetest.takingtest.viewmodel.l lVar) {
        C5041z c5041z = C5041z.a;
        this.b = lVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.questiontypes.selfassessment.h hVar) {
        C5041z c5041z = C5041z.a;
        this.b = hVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(P p) {
        C5041z c5041z = C5041z.a;
        this.b = p;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.settings.viewmodels.k kVar) {
        C5041z c5041z = C5041z.a;
        this.b = kVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.universaluploadflow.flashcards.viewmodel.e eVar) {
        C5041z c5041z = C5041z.a;
        this.b = eVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.universaluploadflow.pastetext.viewmodel.d dVar) {
        C5041z c5041z = C5041z.a;
        this.b = dVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.features.universaluploadflow.viewmodel.g gVar) {
        C5041z c5041z = C5041z.a;
        this.b = gVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.learn.viewmodel.G g) {
        C5041z c5041z = C5041z.a;
        this.b = g;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.library.viewmodels.l lVar) {
        C5041z c5041z = C5041z.a;
        this.b = lVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.library.viewmodels.s sVar) {
        C5041z c5041z = C5041z.a;
        this.b = sVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.quizletandroid.ui.classcreation.i iVar) {
        C5041z c5041z = C5041z.a;
        this.b = iVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(c0 c0Var) {
        C5041z c5041z = C5041z.a;
        this.b = c0Var;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.search.viewmodels.p pVar) {
        C5041z c5041z = C5041z.a;
        this.b = pVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.search.viewmodels.r rVar) {
        C5041z c5041z = C5041z.a;
        this.b = rVar;
        super(c5041z);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C4203d(com.quizlet.search.viewmodels.M m) {
        C5041z c5041z = C5041z.a;
        this.b = m;
        super(c5041z);
    }
}
