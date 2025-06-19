package com.quizlet.features.notes.detail.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.C1372j;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.data.model.R1;
import com.quizlet.data.model.ReviewSheetInfo;
import com.quizlet.data.model.TitleInfo;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.notes.common.events.C4371b;
import com.quizlet.features.notes.common.events.C4372c;
import com.quizlet.features.notes.common.events.C4373d;
import com.quizlet.features.notes.common.events.C4374e;
import com.quizlet.features.notes.common.events.C4375f;
import com.quizlet.features.notes.common.events.C4376g;
import com.quizlet.features.notes.common.events.C4377h;
import com.quizlet.features.notes.common.events.C4378i;
import com.quizlet.features.notes.common.events.C4379j;
import com.quizlet.features.notes.common.events.C4380k;
import com.quizlet.features.notes.common.events.C4381l;
import com.quizlet.features.notes.common.events.w;
import com.quizlet.features.notes.common.events.x;
import com.quizlet.features.notes.common.events.y;
import com.quizlet.features.notes.data.z;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class v extends com.quizlet.features.notes.common.viewmodels.b {
    public final m0 e;
    public final com.quizlet.features.notes.logging.f f;
    public final long g;
    public final com.quizlet.data.repository.login.a h;
    public final com.google.firebase.crashlytics.internal.settings.b i;
    public final G j;
    public final com.google.firebase.messaging.p k;
    public final androidx.work.impl.model.c l;
    public final com.quizlet.data.interactor.achievements.f m;
    public final com.lyft.android.scissors.b n;
    public final com.google.android.material.floatingactionbutton.c o;
    public final com.google.firebase.crashlytics.internal.common.j p;
    public final s0 q;
    public final d0 r;
    public final s0 s;
    public final d0 t;
    public final d0 u;
    public NotesToValueInfo v;
    public final t w;
    public final t x;
    public final t y;
    public boolean z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(m0 stateHandle, com.quizlet.features.notes.logging.f notesEventLogger, long j, com.quizlet.data.interactor.metering.b getMeteringInfo, com.quizlet.data.repository.login.a getStudyNotesByIdUseCase, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, G setPageStudyModesManager, com.google.firebase.messaging.p getStudyNotesArtifactUseCase, androidx.work.impl.model.c shareMagicNotesHelper, com.quizlet.data.interactor.achievements.f deleteNoteUseCase, com.lyft.android.scissors.b updateStudyNotesTitleUseCase, com.google.android.material.floatingactionbutton.c updateStudyNotesPrivacySettingsUseCase, com.google.firebase.crashlytics.internal.common.j updateMagicNotesIntoCacheUseCase, FolderLogger folderEventLogger) {
        super(j, notesEventLogger, getMeteringInfo);
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(getMeteringInfo, "getMeteringInfo");
        Intrinsics.checkNotNullParameter(getStudyNotesByIdUseCase, "getStudyNotesByIdUseCase");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(setPageStudyModesManager, "setPageStudyModesManager");
        Intrinsics.checkNotNullParameter(getStudyNotesArtifactUseCase, "getStudyNotesArtifactUseCase");
        Intrinsics.checkNotNullParameter(shareMagicNotesHelper, "shareMagicNotesHelper");
        Intrinsics.checkNotNullParameter(deleteNoteUseCase, "deleteNoteUseCase");
        Intrinsics.checkNotNullParameter(updateStudyNotesTitleUseCase, "updateStudyNotesTitleUseCase");
        Intrinsics.checkNotNullParameter(updateStudyNotesPrivacySettingsUseCase, "updateStudyNotesPrivacySettingsUseCase");
        Intrinsics.checkNotNullParameter(updateMagicNotesIntoCacheUseCase, "updateMagicNotesIntoCacheUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.e = stateHandle;
        this.f = notesEventLogger;
        this.g = j;
        this.h = getStudyNotesByIdUseCase;
        this.i = checkNotesEligibilityUseCase;
        this.j = setPageStudyModesManager;
        this.k = getStudyNotesArtifactUseCase;
        this.l = shareMagicNotesHelper;
        this.m = deleteNoteUseCase;
        this.n = updateStudyNotesTitleUseCase;
        this.o = updateStudyNotesPrivacySettingsUseCase;
        this.p = updateMagicNotesIntoCacheUseCase;
        this.q = e0.c(com.quizlet.features.notes.detail.states.f.a);
        this.r = e0.b(0, 1, null, 5);
        this.s = e0.c(com.quizlet.features.notes.detail.menu.l.a);
        this.t = e0.b(0, 1, null, 5);
        this.u = e0.b(0, 1, null, 5);
        t tVar = new t(this, 0);
        this.w = tVar;
        this.x = new t(this, 1);
        this.y = new t(this, 2);
        String strC = C();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4465a0.ENTER.a();
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strC, 11);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
        companion.getClass();
        notesEventLogger.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
        folderEventLogger.setScreenName("study_guide");
        E.A(p0.j(this), tVar, null, new e(this, null), 2);
    }

    public final String C() {
        Object objA = this.e.a("uuid");
        if (objA != null) {
            return (String) objA;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0089, code lost:
    
        if (r4.G(null, r0) == r1) goto L32;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object D(boolean r7, kotlin.coroutines.jvm.internal.c r8) throws com.quizlet.data.exceptions.notes.NotesException {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.features.notes.detail.viewmodels.g
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.notes.detail.viewmodels.g r0 = (com.quizlet.features.notes.detail.viewmodels.g) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.notes.detail.viewmodels.g r0 = new com.quizlet.features.notes.detail.viewmodels.g
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L8c
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L32:
            boolean r7 = r0.l
            com.quizlet.features.notes.detail.viewmodels.v r2 = r0.k
            com.quizlet.features.notes.detail.viewmodels.v r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L67
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L3f:
            kotlinx.coroutines.flow.s0 r8 = r6.q
            java.lang.Object r2 = r8.getValue()
            r5 = r2
            com.quizlet.features.notes.detail.states.h r5 = (com.quizlet.features.notes.detail.states.h) r5
            com.quizlet.features.notes.detail.states.f r5 = com.quizlet.features.notes.detail.states.f.a
            boolean r8 = r8.k(r2, r5)
            if (r8 == 0) goto L3f
            java.lang.String r8 = r6.C()
            r0.j = r6
            r0.k = r6
            r0.l = r7
            r0.o = r4
            com.quizlet.data.repository.login.a r2 = r6.h
            java.lang.Object r8 = r2.i(r8, r0, r7)
            if (r8 != r1) goto L65
            goto L8b
        L65:
            r2 = r6
            r4 = r2
        L67:
            com.quizlet.data.model.NotesToValueInfo r8 = (com.quizlet.data.model.NotesToValueInfo) r8
            r2.v = r8
            r8 = 0
            if (r7 == 0) goto L7f
            com.quizlet.data.model.NotesToValueInfo r7 = r4.v
            if (r7 == 0) goto L79
            r4.B(r7)
            r4.E()
            goto L7f
        L79:
            java.lang.String r7 = "magicNotes"
            kotlin.jvm.internal.Intrinsics.m(r7)
            throw r8
        L7f:
            r0.j = r8
            r0.k = r8
            r0.o = r3
            java.lang.Object r7 = r4.G(r8, r0)
            if (r7 != r1) goto L8c
        L8b:
            return r1
        L8c:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.v.D(boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void E() {
        NotesToValueInfo notesToValueInfo = this.v;
        if (notesToValueInfo == null) {
            Intrinsics.m("magicNotes");
            throw null;
        }
        EssayInfo essayInfo = notesToValueInfo.g;
        EnumC4175w enumC4175w = essayInfo != null ? essayInfo.b : null;
        EnumC4175w enumC4175w2 = EnumC4175w.COMPLETE;
        final int i = enumC4175w == enumC4175w2 ? 1 : 0;
        FlashcardsInfo flashcardsInfo = notesToValueInfo.f;
        if ((flashcardsInfo != null ? flashcardsInfo.b : null) == enumC4175w2) {
            i++;
        }
        OutlineMarkdownInfo outlineMarkdownInfo = notesToValueInfo.d;
        if ((outlineMarkdownInfo != null ? outlineMarkdownInfo.b : null) == enumC4175w2) {
            i++;
        }
        final boolean z = (essayInfo != null ? essayInfo.b : null) == enumC4175w2;
        final boolean z2 = (flashcardsInfo != null ? flashcardsInfo.b : null) == enumC4175w2;
        final boolean z3 = (outlineMarkdownInfo != null ? outlineMarkdownInfo.b : null) == enumC4175w2;
        com.quizlet.features.notes.logging.f fVar = this.f;
        fVar.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4465a0.TOTAL_ARTIFACTS_GENERATED.a();
        Function1 function1 = new Function1() { // from class: com.quizlet.features.notes.logging.d
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                NotesEventLog.Payload createEvent = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setEssay_prompts(Boolean.valueOf(z));
                createEvent.setFlashcards(Boolean.valueOf(z2));
                createEvent.setOutline(Boolean.valueOf(z3));
                createEvent.setArtifactCount(Integer.valueOf(i));
                return Unit.a;
            }
        };
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, function1));
    }

    public final void F(y event) {
        s0 s0Var;
        Object value;
        Long l;
        okhttp3.s sVarD;
        String artifactName;
        Long l2;
        Long l3;
        Long l4;
        Long l5;
        Intrinsics.checkNotNullParameter(event, "event");
        if (Intrinsics.b(event, x.a)) {
            m0 m0Var = this.e;
            AddMaterialFolderData addMaterialFolderData = (AddMaterialFolderData) m0Var.a("addMaterialFolderData");
            if (addMaterialFolderData != null) {
                this.u.h(new com.quizlet.features.infra.folder.menu.data.a(C(), y1.NOTE, addMaterialFolderData));
                return;
            }
            return;
        }
        String str = null;
        if (Intrinsics.b(event, C4374e.a)) {
            Object value2 = this.q.getValue();
            E.A(p0.j(this), null, null, new j(value2 instanceof com.quizlet.features.notes.detail.states.e ? (com.quizlet.features.notes.detail.states.e) value2 : null, this, null), 3);
            return;
        }
        boolean zB = Intrinsics.b(event, C4375f.a);
        com.quizlet.features.notes.logging.f fVar = this.f;
        if (zB) {
            String strC = C();
            fVar.getClass();
            NotesEventLog.Companion companion = NotesEventLog.b;
            String strA = EnumC4465a0.NOTE_CREATOR_PROFILE_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strC, 9);
            EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
            companion.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
            return;
        }
        boolean zB2 = Intrinsics.b(event, C4376g.a);
        d0 d0Var = this.r;
        if (zB2) {
            String strC2 = C();
            fVar.getClass();
            NotesEventLog.Companion companion2 = NotesEventLog.b;
            String strA2 = EnumC4465a0.FLASHCARDS_EDIT_SET_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar2 = new com.quizlet.features.notes.logging.c(strC2, 6);
            EnumC4503n enumC4503n2 = com.quizlet.features.notes.logging.a.c;
            companion2.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n2, strA2, cVar2));
            NotesToValueInfo notesToValueInfo = this.v;
            if (notesToValueInfo == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            FlashcardsInfo flashcardsInfo = notesToValueInfo.f;
            if (flashcardsInfo == null || (l5 = flashcardsInfo.c) == null) {
                return;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.d(l5.longValue()));
            return;
        }
        if (Intrinsics.b(event, C4377h.a)) {
            String strC3 = C();
            fVar.getClass();
            NotesEventLog.Companion companion3 = NotesEventLog.b;
            String strA3 = EnumC4465a0.ESSAY_PROMPTS_VIEW_ALL_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar3 = new com.quizlet.features.notes.logging.c(strC3, 13);
            EnumC4503n enumC4503n3 = com.quizlet.features.notes.logging.a.c;
            companion3.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n3, strA3, cVar3));
            d0Var.h(new com.quizlet.features.notes.detail.events.e(C()));
            return;
        }
        if (Intrinsics.b(event, C4378i.a)) {
            String strC4 = C();
            fVar.getClass();
            NotesEventLog.Companion companion4 = NotesEventLog.b;
            String strA4 = EnumC4465a0.FLASHCARDS_FLIPPED.a();
            androidx.navigation.internal.h hVar = new androidx.navigation.internal.h(strC4, 24);
            EnumC4503n enumC4503n4 = com.quizlet.features.notes.logging.a.c;
            companion4.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n4, strA4, hVar));
            return;
        }
        if (Intrinsics.b(event, C4379j.a)) {
            String strC5 = C();
            fVar.getClass();
            NotesEventLog.Companion companion5 = NotesEventLog.b;
            String strA5 = EnumC4465a0.FLASHCARDS_FULLSCREEN_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar4 = new com.quizlet.features.notes.logging.c(strC5, 17);
            EnumC4503n enumC4503n5 = com.quizlet.features.notes.logging.a.c;
            companion5.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n5, strA5, cVar4));
            NotesToValueInfo notesToValueInfo2 = this.v;
            if (notesToValueInfo2 == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            FlashcardsInfo flashcardsInfo2 = notesToValueInfo2.f;
            if (flashcardsInfo2 == null || (l4 = flashcardsInfo2.c) == null) {
                return;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.f(l4.longValue()));
            return;
        }
        if (Intrinsics.b(event, C4380k.a)) {
            String strC6 = C();
            fVar.getClass();
            NotesEventLog.Companion companion6 = NotesEventLog.b;
            String strA6 = EnumC4465a0.FLASHCARDS_ARROW_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar5 = new com.quizlet.features.notes.logging.c(strC6, 15);
            EnumC4503n enumC4503n6 = com.quizlet.features.notes.logging.a.c;
            companion6.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n6, strA6, cVar5));
            return;
        }
        if (Intrinsics.b(event, C4381l.a)) {
            String strC7 = C();
            fVar.getClass();
            NotesEventLog.Companion companion7 = NotesEventLog.b;
            String strA7 = EnumC4465a0.STUDY_MODE_LEARN_SHORTCUT_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar6 = new com.quizlet.features.notes.logging.c(strC7, 5);
            EnumC4503n enumC4503n7 = com.quizlet.features.notes.logging.a.c;
            companion7.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n7, strA7, cVar6));
            NotesToValueInfo notesToValueInfo3 = this.v;
            if (notesToValueInfo3 == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            FlashcardsInfo flashcardsInfo3 = notesToValueInfo3.f;
            if (flashcardsInfo3 == null || (l3 = flashcardsInfo3.c) == null) {
                return;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.h(l3.longValue()));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.notes.common.events.m.a)) {
            String strC8 = C();
            fVar.getClass();
            NotesEventLog.Companion companion8 = NotesEventLog.b;
            String strA8 = EnumC4465a0.STUDY_MODE_MATCH_SHORTCUT_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar7 = new com.quizlet.features.notes.logging.c(strC8, 8);
            EnumC4503n enumC4503n8 = com.quizlet.features.notes.logging.a.c;
            companion8.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n8, strA8, cVar7));
            NotesToValueInfo notesToValueInfo4 = this.v;
            if (notesToValueInfo4 == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            FlashcardsInfo flashcardsInfo4 = notesToValueInfo4.f;
            if (flashcardsInfo4 == null || (l2 = flashcardsInfo4.c) == null) {
                return;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.i(l2.longValue()));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.notes.common.events.p.a)) {
            E.A(p0.j(this), this.x, null, new m(this, null), 2);
            return;
        }
        boolean z = event instanceof com.quizlet.features.notes.common.events.q;
        t tVar = this.w;
        if (z) {
            E.A(p0.j(this), tVar, null, new o(this, ((com.quizlet.features.notes.common.events.q) event).a, null), 2);
            return;
        }
        if (event instanceof com.quizlet.features.notes.common.events.r) {
            E.A(p0.j(this), this.y, null, new p(this, ((com.quizlet.features.notes.common.events.r) event).a, null), 2);
            return;
        }
        if (event instanceof com.quizlet.features.notes.common.events.s) {
            R1 r1 = ((com.quizlet.features.notes.common.events.s) event).a;
            Intrinsics.checkNotNullParameter(r1, "<this>");
            if (r1 instanceof EssayInfo) {
                artifactName = "ESSAY_PROMPTS".toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(artifactName, "toLowerCase(...)");
            } else if (r1 instanceof FlashcardsInfo) {
                artifactName = "TERM_SET".toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(artifactName, "toLowerCase(...)");
            } else if (r1 instanceof TitleInfo) {
                artifactName = "TITLE".toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(artifactName, "toLowerCase(...)");
            } else if (r1 instanceof OutlineMarkdownInfo) {
                artifactName = "OUTLINE_MARKDOWN".toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(artifactName, "toLowerCase(...)");
            } else {
                if (!(r1 instanceof ReviewSheetInfo)) {
                    throw new NoWhenBranchMatchedException();
                }
                artifactName = "REVIEW_SHEET".toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(artifactName, "toLowerCase(...)");
            }
            String strC9 = C();
            fVar.getClass();
            Intrinsics.checkNotNullParameter(artifactName, "artifactName");
            NotesEventLog.Companion companion9 = NotesEventLog.b;
            String strA9 = EnumC4465a0.REFRESH_CLICKED.a();
            com.braze.ui.e eVar = new com.braze.ui.e(7, artifactName, strC9);
            EnumC4503n enumC4503n9 = com.quizlet.features.notes.logging.a.c;
            companion9.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n9, strA9, eVar));
            E.A(p0.j(this), tVar, null, new s(this, r1, null), 2);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.notes.common.events.t.a)) {
            E.A(p0.j(this), tVar, null, new q(this, null), 2);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.notes.common.events.u.a)) {
            String strC10 = C();
            fVar.getClass();
            NotesEventLog.Companion companion10 = NotesEventLog.b;
            String strA10 = EnumC4465a0.SETTINGS_ICON_CLICKED.a();
            androidx.navigation.internal.h hVar2 = new androidx.navigation.internal.h(strC10, 29);
            EnumC4503n enumC4503n10 = com.quizlet.features.notes.logging.a.c;
            companion10.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n10, strA10, hVar2));
            E.A(p0.j(this), null, null, new r(this, null), 3);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.notes.common.events.v.a)) {
            String strC11 = C();
            fVar.getClass();
            NotesEventLog.Companion companion11 = NotesEventLog.b;
            String strA11 = EnumC4465a0.SHARE_NOTE_CLICKED.a();
            androidx.navigation.internal.h hVar3 = new androidx.navigation.internal.h(strC11, 25);
            EnumC4503n enumC4503n11 = com.quizlet.features.notes.logging.a.c;
            companion11.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n11, strA11, hVar3));
            NotesToValueInfo notesToValueInfo5 = this.v;
            if (notesToValueInfo5 == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            TitleInfo titleInfo = notesToValueInfo5.c;
            String str2 = titleInfo != null ? titleInfo.c : null;
            if (str2 == null) {
                str2 = "";
            }
            androidx.work.impl.model.c cVar8 = this.l;
            com.quizlet.utmhelper.a aVar = new com.quizlet.utmhelper.a(Long.valueOf(((UserInfoCache) cVar8.b).getPersonId()), "note-page-share", "share-link", "share-sheet-android");
            String strC12 = C();
            String noteUuid = C();
            Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
            String strConcat = "https://quizlet.com/study-guides/".concat(noteUuid);
            Intrinsics.checkNotNullParameter(strConcat, "<this>");
            try {
                Intrinsics.checkNotNullParameter(strConcat, "<this>");
                C1372j c1372j = new C1372j();
                c1372j.l(null, strConcat);
                sVarD = c1372j.d();
            } catch (IllegalArgumentException unused) {
                sVarD = null;
            }
            if (sVarD != null) {
                C1372j c1372jF = sVarD.f();
                com.quizlet.utmhelper.b bVarA = ((com.quizlet.utmhelper.d) ((com.quizlet.utmhelper.c) cVar8.c)).a(new com.quizlet.utmhelper.a(Long.valueOf(((UserInfoCache) cVar8.b).getPersonId()), "note-page-share", "share-link", "share-sheet-android"));
                c1372jF.c("x", bVarA.b);
                c1372jF.c("i", bVarA.a);
                str = c1372jF.d().i;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.l(str2, new z(aVar, strC12, str != null ? str : "")));
            return;
        }
        if (Intrinsics.b(event, w.a)) {
            String strC13 = C();
            fVar.getClass();
            NotesEventLog.Companion companion12 = NotesEventLog.b;
            String strA12 = EnumC4465a0.TAKE_PRACTICE_TEST_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar9 = new com.quizlet.features.notes.logging.c(strC13, 7);
            EnumC4503n enumC4503n12 = com.quizlet.features.notes.logging.a.c;
            companion12.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n12, strA12, cVar9));
            NotesToValueInfo notesToValueInfo6 = this.v;
            if (notesToValueInfo6 == null) {
                Intrinsics.m("magicNotes");
                throw null;
            }
            FlashcardsInfo flashcardsInfo5 = notesToValueInfo6.f;
            if (flashcardsInfo5 == null || (l = flashcardsInfo5.c) == null) {
                return;
            }
            d0Var.h(new com.quizlet.features.notes.detail.events.n(l.longValue()));
            return;
        }
        if (event instanceof C4371b) {
            com.quizlet.features.notes.data.x xVar = ((C4371b) event).a;
            if (Intrinsics.b(xVar, com.quizlet.features.notes.data.p.a)) {
                E.A(p0.j(this), tVar, null, new l(this, null), 2);
                return;
            } else {
                if (Intrinsics.b(xVar, com.quizlet.features.notes.data.n.a) || (xVar instanceof com.quizlet.features.notes.data.s) || (xVar instanceof com.quizlet.features.notes.data.i)) {
                    d0Var.h(com.quizlet.features.notes.detail.events.o.a);
                    return;
                }
                return;
            }
        }
        if (Intrinsics.b(event, C4372c.a)) {
            d0Var.h(com.quizlet.features.notes.detail.events.g.a);
            return;
        }
        if (Intrinsics.b(event, C4373d.a)) {
            d0Var.h(com.quizlet.features.notes.detail.events.m.a);
            return;
        }
        if (!(event instanceof com.quizlet.features.notes.common.events.o)) {
            if (Intrinsics.b(event, com.quizlet.features.notes.common.events.n.a)) {
                do {
                    s0Var = this.s;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.features.notes.detail.menu.l.a));
                return;
            }
            return;
        }
        com.quizlet.features.notes.detail.menu.f fVar2 = ((com.quizlet.features.notes.common.events.o) event).a;
        boolean zB3 = Intrinsics.b(fVar2, com.quizlet.features.notes.detail.menu.a.a);
        d0 d0Var2 = this.t;
        if (zB3) {
            String strC14 = C();
            fVar.getClass();
            NotesEventLog.Companion companion13 = NotesEventLog.b;
            String strA13 = EnumC4465a0.DELETE_NOTE_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar10 = new com.quizlet.features.notes.logging.c(strC14, 3);
            EnumC4503n enumC4503n13 = com.quizlet.features.notes.logging.a.c;
            companion13.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n13, strA13, cVar10));
            d0Var2.h(com.quizlet.features.notes.detail.menu.g.a);
            return;
        }
        if (Intrinsics.b(fVar2, com.quizlet.features.notes.detail.menu.b.a)) {
            E.A(p0.j(this), tVar, null, new k(this, null), 2);
            return;
        }
        if (Intrinsics.b(fVar2, com.quizlet.features.notes.detail.menu.c.a)) {
            String strC15 = C();
            fVar.getClass();
            NotesEventLog.Companion companion14 = NotesEventLog.b;
            String strA14 = EnumC4465a0.PRIVACY_SETTINGS_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar11 = new com.quizlet.features.notes.logging.c(strC15, 1);
            EnumC4503n enumC4503n14 = com.quizlet.features.notes.logging.a.c;
            companion14.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n14, strA14, cVar11));
            d0Var2.h(com.quizlet.features.notes.detail.menu.i.a);
            return;
        }
        if (Intrinsics.b(fVar2, com.quizlet.features.notes.detail.menu.d.a)) {
            String strC16 = C();
            fVar.getClass();
            NotesEventLog.Companion companion15 = NotesEventLog.b;
            String strA15 = EnumC4465a0.REPORT_CONTENT_CLICKED.a();
            androidx.navigation.internal.h hVar4 = new androidx.navigation.internal.h(strC16, 23);
            EnumC4503n enumC4503n15 = com.quizlet.features.notes.logging.a.c;
            companion15.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n15, strA15, hVar4));
            d0Var.h(new com.quizlet.features.notes.detail.events.k(C()));
            return;
        }
        if (!Intrinsics.b(fVar2, com.quizlet.features.notes.detail.menu.e.a)) {
            throw new NoWhenBranchMatchedException();
        }
        String strC17 = C();
        fVar.getClass();
        NotesEventLog.Companion companion16 = NotesEventLog.b;
        String strA16 = EnumC4465a0.ORIGINAL_UPLOAD_MODAL_VIEWED.a();
        com.quizlet.features.notes.logging.c cVar12 = new com.quizlet.features.notes.logging.c(strC17, 12);
        EnumC4503n enumC4503n16 = com.quizlet.features.notes.logging.a.c;
        companion16.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n16, strA16, cVar12));
        d0Var2.h(com.quizlet.features.notes.detail.menu.j.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:74:0x0121, code lost:
    
        r15 = 2;
        r18 = r10;
        r17 = r11;
        r19 = r14;
        r21 = false;
        r14 = r1;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00be  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x010e  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x012d  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0134  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0162  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:48:0x00fb -> B:49:0x0100). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object G(com.quizlet.features.notes.data.c r25, kotlin.coroutines.jvm.internal.c r26) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 366
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.v.G(com.quizlet.features.notes.data.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        String strC = C();
        com.quizlet.features.notes.logging.f fVar = this.f;
        fVar.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4465a0.EXIT.a();
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strC, 2);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
    }
}
