package com.quizlet.features.notes.upload.viewmodels;

import android.net.Uri;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.quizlet.data.model.m2;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.eventlogger.model.ScanNotesMeteringToastEventLog;
import com.quizlet.features.notes.common.events.B;
import com.quizlet.features.notes.common.events.C;
import com.quizlet.features.notes.common.events.C4371b;
import com.quizlet.features.notes.common.events.F;
import com.quizlet.features.notes.common.events.G;
import com.quizlet.features.notes.common.events.H;
import com.quizlet.features.notes.common.events.I;
import com.quizlet.features.notes.common.events.J;
import com.quizlet.features.notes.common.events.L;
import com.quizlet.features.notes.common.events.y;
import com.quizlet.features.notes.data.l;
import com.quizlet.features.notes.data.m;
import com.quizlet.features.notes.data.n;
import com.quizlet.features.notes.data.o;
import com.quizlet.features.notes.data.p;
import com.quizlet.features.notes.data.q;
import com.quizlet.features.notes.data.r;
import com.quizlet.features.notes.data.t;
import com.quizlet.features.notes.data.u;
import com.quizlet.features.notes.data.v;
import com.quizlet.features.notes.data.x;
import com.quizlet.generated.enums.C4486h0;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.generated.enums.EnumC4489i0;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class k extends c {
    public final LinkedHashSet A;
    public final m0 q;
    public final com.quizlet.features.notes.logging.f r;
    public final com.google.firebase.crashlytics.internal.settings.b s;
    public final com.quizlet.features.notes.a t;
    public final com.quizlet.data.repository.explanations.question.a u;
    public final androidx.work.impl.background.greedy.d v;
    public final com.quizlet.data.repository.set.f w;
    public final s0 x;
    public com.quizlet.features.notes.data.d y;
    public List z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m0 stateHandle, com.quizlet.features.notes.logging.f notesEventLogger, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMinimum, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMaximum, com.quizlet.data.repository.explanations.question.a magicNotesFileMaximumSize, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, com.quizlet.features.notes.a scanNotesMeteringToastEventLogger, com.quizlet.data.interactor.metering.b getMeteringInfo, long j, com.quizlet.data.repository.explanations.question.a magicNotesMeteringValue, androidx.work.impl.background.greedy.d createStudyNotesWithFileUseCase, com.quizlet.data.repository.set.f fileHelper, com.google.firebase.crashlytics.internal.settings.b addStudyMaterialToFolderUseCase) {
        super(stateHandle, notesEventLogger, j, getMeteringInfo, magicNotesCharacterMinimum, magicNotesCharacterMaximum, magicNotesFileMaximumSize, addStudyMaterialToFolderUseCase);
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMinimum, "magicNotesCharacterMinimum");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMaximum, "magicNotesCharacterMaximum");
        Intrinsics.checkNotNullParameter(magicNotesFileMaximumSize, "magicNotesFileMaximumSize");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(scanNotesMeteringToastEventLogger, "scanNotesMeteringToastEventLogger");
        Intrinsics.checkNotNullParameter(getMeteringInfo, "getMeteringInfo");
        Intrinsics.checkNotNullParameter(magicNotesMeteringValue, "magicNotesMeteringValue");
        Intrinsics.checkNotNullParameter(createStudyNotesWithFileUseCase, "createStudyNotesWithFileUseCase");
        Intrinsics.checkNotNullParameter(fileHelper, "fileHelper");
        Intrinsics.checkNotNullParameter(addStudyMaterialToFolderUseCase, "addStudyMaterialToFolderUseCase");
        this.q = stateHandle;
        this.r = notesEventLogger;
        this.s = checkNotesEligibilityUseCase;
        this.t = scanNotesMeteringToastEventLogger;
        this.u = magicNotesMeteringValue;
        this.v = createStudyNotesWithFileUseCase;
        this.w = fileHelper;
        this.x = e0.c(com.quizlet.features.notes.upload.states.b.a);
        C4486h0 c4486h0 = EnumC4489i0.Companion;
        this.y = com.quizlet.features.notes.data.d.c;
        this.z = K.a;
        this.A = new LinkedHashSet();
        notesEventLogger.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.UPLOAD_SCREEN_VIEW.a()));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object K(com.quizlet.features.notes.upload.viewmodels.k r5, com.quizlet.data.model.InterfaceC4176w0 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof com.quizlet.features.notes.upload.viewmodels.j
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.features.notes.upload.viewmodels.j r0 = (com.quizlet.features.notes.upload.viewmodels.j) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.notes.upload.viewmodels.j r0 = new com.quizlet.features.notes.upload.viewmodels.j
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = -1
            r4 = 1
            if (r2 == 0) goto L37
            if (r2 != r4) goto L2f
            int r5 = r0.k
            int r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5a
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            boolean r7 = r6 instanceof com.quizlet.data.model.C4179x0
            if (r7 == 0) goto L63
            com.quizlet.data.model.x0 r6 = (com.quizlet.data.model.C4179x0) r6
            int r7 = r6.b
            int r6 = r6.a
            int r6 = r7 - r6
            r0.j = r6
            r0.k = r6
            r0.n = r4
            com.quizlet.data.repository.explanations.question.a r5 = r5.u
            java.lang.Object r7 = r5.c
            java.lang.Integer r7 = (java.lang.Integer) r7
            java.lang.Object r7 = r5.d(r7)
            if (r7 != r1) goto L59
            return r1
        L59:
            r5 = r6
        L5a:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            if (r5 > r7) goto L63
            r3 = r6
        L63:
            java.lang.Integer r5 = new java.lang.Integer
            r5.<init>(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.k.K(com.quizlet.features.notes.upload.viewmodels.k, com.quizlet.data.model.w0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.features.notes.upload.viewmodels.c
    public final X E() {
        return this.x;
    }

    @Override // com.quizlet.features.notes.upload.viewmodels.c
    public final void G(String str) {
        com.quizlet.features.notes.logging.f fVar = this.r;
        fVar.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4471c0.COMPUTER_FILE_ERROR.a();
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(str, 0);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.b;
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
    }

    @Override // com.quizlet.features.notes.upload.viewmodels.c
    public final void H() {
        com.quizlet.features.notes.data.d dVar = this.y;
        com.quizlet.features.notes.data.d dVar2 = com.quizlet.features.notes.data.d.b;
        com.quizlet.features.notes.logging.f fVar = this.r;
        if (dVar == dVar2) {
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.PHOTO_DETECTED_TEXT_UNDER_LIMIT.a()));
            return;
        }
        fVar.getClass();
        fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_FILE_DETECTED_TEXT_UNDER_LIMIT.a()));
    }

    @Override // com.quizlet.features.notes.upload.viewmodels.c
    public final void I() {
        com.quizlet.features.notes.data.d dVar = this.y;
        com.quizlet.features.notes.data.d dVar2 = com.quizlet.features.notes.data.d.b;
        com.quizlet.features.notes.logging.f fVar = this.r;
        if (dVar == dVar2) {
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.PHOTO_DETECTED_TEXT_OVER_LIMIT.a()));
            return;
        }
        fVar.getClass();
        fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_FILE_DETECTED_TEXT_OVER_LIMIT.a()));
    }

    public final void L(List list) {
        com.quizlet.features.notes.data.d dVar;
        LinkedHashSet linkedHashSet;
        this.y = com.quizlet.features.notes.data.d.c;
        com.quizlet.data.repository.set.f fVar = this.w;
        if (list == null || !list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                String uriString = ((Uri) it2.next()).toString();
                Intrinsics.checkNotNullExpressionValue(uriString, "toString(...)");
                fVar.getClass();
                Intrinsics.checkNotNullParameter(uriString, "uriString");
                String strH = fVar.h(uriString);
                if (strH == null || !D.r(strH, "image/", false)) {
                    dVar = com.quizlet.features.notes.data.d.c;
                    break;
                }
            }
            dVar = com.quizlet.features.notes.data.d.b;
        } else {
            dVar = com.quizlet.features.notes.data.d.b;
        }
        this.y = dVar;
        Iterator it3 = list.iterator();
        while (true) {
            boolean zHasNext = it3.hasNext();
            linkedHashSet = this.A;
            if (!zHasNext) {
                break;
            }
            String string = ((Uri) it3.next()).toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            String strH2 = fVar.h(string);
            if (strH2 != null) {
                linkedHashSet.add(strH2);
            }
        }
        String lowerCase = this.y.name().toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        List listW0 = CollectionsKt.w0(linkedHashSet);
        com.quizlet.features.notes.logging.f fVar2 = this.r;
        com.quizlet.features.notes.logging.f.d(fVar2, lowerCase, null, listW0, 2);
        if (!list.isEmpty()) {
            Iterator it4 = list.iterator();
            while (it4.hasNext()) {
                String uriString2 = ((Uri) it4.next()).toString();
                Intrinsics.checkNotNullExpressionValue(uriString2, "toString(...)");
                fVar.getClass();
                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                String strH3 = fVar.h(uriString2);
                if (strH3 == null || !D.r(strH3, "image/", false)) {
                    O(list);
                    return;
                }
            }
        }
        fVar2.getClass();
        fVar2.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_FILE_ADDED.a()));
        this.y = com.quizlet.features.notes.data.d.b;
        E.A(p0.j(this), this.p, null, new g(this, list, null), 2);
    }

    public final void M(String str) {
        String lowerCase = "TEXT".toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        com.quizlet.features.notes.logging.f.d(this.r, lowerCase, Integer.valueOf(str.length()), null, 4);
        this.q.b("text");
        this.k.h(new com.quizlet.features.notes.upload.events.d(D(), this.l, str, C()));
    }

    public final void N(y event) {
        Object value;
        com.quizlet.features.notes.upload.states.a aVar;
        m2 source;
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof C4371b) {
            x xVar = ((C4371b) event).a;
            if (Intrinsics.b(xVar, p.a)) {
                O(this.z);
                return;
            }
            if (Intrinsics.b(xVar, q.a) || Intrinsics.b(xVar, com.quizlet.features.notes.data.g.a) || Intrinsics.b(xVar, l.a) || Intrinsics.b(xVar, v.a) || Intrinsics.b(xVar, com.quizlet.features.notes.data.h.a) || Intrinsics.b(xVar, com.quizlet.features.notes.data.k.a) || Intrinsics.b(xVar, o.a) || Intrinsics.b(xVar, u.a) || (xVar instanceof com.quizlet.features.notes.data.j) || (xVar instanceof t) || (xVar instanceof r) || (xVar instanceof n) || (xVar instanceof m)) {
                E.A(p0.j(this), null, null, new f(this, null), 3);
                return;
            }
            return;
        }
        boolean zB = Intrinsics.b(event, C.a);
        com.quizlet.features.notes.a aVar2 = this.t;
        if (zB) {
            aVar2.getClass();
            aVar2.a.l(new ScanNotesMeteringToastEventLog("notes_toast", "notes_to_value_headsup_dismiss_clicked"));
            E.A(p0.j(this), null, null, new h(Boolean.FALSE, this, null), 3);
            return;
        }
        boolean z = event instanceof com.quizlet.features.notes.common.events.D;
        com.quizlet.features.notes.logging.f fVar = this.r;
        if (z) {
            List list = ((com.quizlet.features.notes.common.events.D) event).a;
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_FILE_ADDED.a()));
            this.y = com.quizlet.features.notes.data.d.c;
            O(list);
            return;
        }
        if (event instanceof com.quizlet.features.notes.common.events.E) {
            List list2 = ((com.quizlet.features.notes.common.events.E) event).a;
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_FILE_ADDED.a()));
            this.y = com.quizlet.features.notes.data.d.b;
            E.A(p0.j(this), this.p, null, new g(this, list2, null), 2);
            return;
        }
        if (Intrinsics.b(event, F.a)) {
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.TEXT_TAB_CLICKED.a()));
            return;
        }
        if (Intrinsics.b(event, I.a)) {
            this.y = com.quizlet.features.notes.data.d.c;
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.COMPUTER_TAB_CLICKED.a()));
            return;
        }
        if (Intrinsics.b(event, J.a)) {
            this.y = com.quizlet.features.notes.data.d.b;
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.IMAGE_TAB_CLICKED.a()));
            return;
        }
        boolean zB2 = Intrinsics.b(event, H.a);
        d0 d0Var = this.k;
        if (zB2) {
            d0Var.h(com.quizlet.features.notes.upload.events.f.a);
            fVar.getClass();
            fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.PHOTO_TAB_CLICKED.a()));
            return;
        }
        if (Intrinsics.b(event, L.a)) {
            aVar2.getClass();
            aVar2.a.l(new ScanNotesMeteringToastEventLog("notes_toast", "notes_to_value_headsup_ugprade_clicked"));
            d0Var.h(com.quizlet.features.notes.upload.events.h.a);
            return;
        }
        if (!(event instanceof G)) {
            if (Intrinsics.b(event, com.quizlet.features.notes.common.events.K.a)) {
                fVar.getClass();
                fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.SETTINGS_CLICKED.a()));
                return;
            } else {
                if (Intrinsics.b(event, B.a)) {
                    d0Var.h(new com.quizlet.features.notes.upload.events.b(C()));
                    return;
                }
                return;
            }
        }
        boolean z2 = ((G) event).a;
        fVar.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4471c0.PRIVACY_SETTINGS_CLICKED.a();
        com.quizlet.assembly.compose.modals.g gVar = new com.quizlet.assembly.compose.modals.g(z2, 4);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.b;
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, gVar));
        this.q.c(Boolean.valueOf(!z2), "isPrivate");
        s0 s0Var = this.x;
        Object value2 = s0Var.getValue();
        if ((value2 instanceof com.quizlet.features.notes.upload.states.a ? (com.quizlet.features.notes.upload.states.a) value2 : null) != null) {
            do {
                value = s0Var.getValue();
                Object value3 = s0Var.getValue();
                Intrinsics.e(value3, "null cannot be cast to non-null type com.quizlet.features.notes.upload.states.MainUploadNotesUiState.Idle");
                aVar = (com.quizlet.features.notes.upload.states.a) value3;
                source = aVar.a;
                Intrinsics.checkNotNullParameter(source, "source");
            } while (!s0Var.k(value, new com.quizlet.features.notes.upload.states.a(source, aVar.b, aVar.c, z2, aVar.e, aVar.f)));
        }
    }

    public final void O(List list) {
        this.z = list;
        E.A(p0.j(this), this.p, null, new i(this, list, null), 2);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        com.quizlet.features.notes.logging.f fVar = this.r;
        fVar.getClass();
        fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.IMPORT_MODAL_CLOSE_CLICK.a()));
    }
}
