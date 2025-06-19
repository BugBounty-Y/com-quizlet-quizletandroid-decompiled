package com.quizlet.features.notes.common.viewmodels;

import androidx.lifecycle.w0;
import androidx.navigation.internal.h;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I6;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.features.notes.logging.c;
import com.quizlet.features.notes.logging.f;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b extends w0 {
    public final long b;
    public final f c;
    public final com.quizlet.data.interactor.metering.b d;

    public b(long j, f notesEventLogger, com.quizlet.data.interactor.metering.b getMeteringInfo) {
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(getMeteringInfo, "getMeteringInfo");
        this.b = j;
        this.c = notesEventLogger;
        this.d = getMeteringInfo;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object A(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.quizlet.features.notes.common.viewmodels.a
            if (r0 == 0) goto L14
            r0 = r9
            com.quizlet.features.notes.common.viewmodels.a r0 = (com.quizlet.features.notes.common.viewmodels.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.features.notes.common.viewmodels.a r0 = new com.quizlet.features.notes.common.viewmodels.a
            r0.<init>(r8, r9)
            goto L12
        L1a:
            java.lang.Object r9 = r7.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.m
            r2 = 1
            if (r1 == 0) goto L33
            if (r1 != r2) goto L2b
            com.quizlet.features.notes.common.viewmodels.b r0 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4a
        L2b:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.generated.enums.P r5 = com.quizlet.generated.enums.P.MAGIC_NOTES_UPLOAD
            r7.j = r8
            r7.m = r2
            long r2 = r8.b
            r4 = 0
            com.quizlet.data.interactor.metering.b r1 = r8.d
            r6 = 1
            java.io.Serializable r9 = r1.a(r2, r4, r5, r6, r7)
            if (r9 != r0) goto L49
            return r0
        L49:
            r0 = r8
        L4a:
            r1 = r9
            com.quizlet.data.model.w0 r1 = (com.quizlet.data.model.InterfaceC4176w0) r1
            r0.getClass()
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.common.viewmodels.b.A(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B(NotesToValueInfo magicNotes) {
        Intrinsics.checkNotNullParameter(magicNotes, "magicNotes");
        boolean zE = I6.e(magicNotes.c);
        f fVar = this.c;
        String str = magicNotes.a;
        if (zE) {
            fVar.getClass();
            NotesEventLog.Companion companion = NotesEventLog.b;
            String strA = EnumC4465a0.TITLE_ERROR_LOADING.a();
            c cVar = new c(str, 19);
            EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
            companion.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
        }
        if (I6.e(magicNotes.d)) {
            fVar.getClass();
            NotesEventLog.Companion companion2 = NotesEventLog.b;
            String strA2 = EnumC4465a0.OUTLINE_ERROR_LOADING.a();
            c cVar2 = new c(str, 14);
            EnumC4503n enumC4503n2 = com.quizlet.features.notes.logging.a.c;
            companion2.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n2, strA2, cVar2));
        }
        if (I6.e(magicNotes.g)) {
            fVar.getClass();
            NotesEventLog.Companion companion3 = NotesEventLog.b;
            String strA3 = EnumC4465a0.ESSAY_PROMPTS_ERROR_LOADING.a();
            h hVar = new h(str, 27);
            EnumC4503n enumC4503n3 = com.quizlet.features.notes.logging.a.c;
            companion3.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n3, strA3, hVar));
        }
        if (I6.e(magicNotes.f)) {
            fVar.getClass();
            NotesEventLog.Companion companion4 = NotesEventLog.b;
            String strA4 = EnumC4465a0.FLASHCARDS_ERROR_LOADING.a();
            h hVar2 = new h(str, 28);
            EnumC4503n enumC4503n4 = com.quizlet.features.notes.logging.a.c;
            companion4.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n4, strA4, hVar2));
        }
    }
}
