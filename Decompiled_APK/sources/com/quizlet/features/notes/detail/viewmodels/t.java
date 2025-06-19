package com.quizlet.features.notes.detail.viewmodels;

import androidx.lifecycle.p0;
import com.quizlet.data.exceptions.notes.DeleteNoteException;
import com.quizlet.data.exceptions.notes.ModerationException;
import com.quizlet.data.exceptions.notes.NoInternetStudyNotesException;
import com.quizlet.data.exceptions.notes.NotFoundNotesException;
import com.quizlet.data.exceptions.notes.PrivateNotesException;
import com.quizlet.data.exceptions.notes.UpdatePrivacySettingsException;
import com.quizlet.data.exceptions.notes.UpdateTitleException;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.a implements A {
    public final /* synthetic */ int a;
    public final /* synthetic */ v b;

    /* JADX WARN: Illegal instructions before constructor call */
    public t(v vVar, int i) {
        this.a = i;
        switch (i) {
            case 1:
                C5041z c5041z = C5041z.a;
                this.b = vVar;
                super(c5041z);
                break;
            case 2:
                C5041z c5041z2 = C5041z.a;
                this.b = vVar;
                super(c5041z2);
                break;
            default:
                C5041z c5041z3 = C5041z.a;
                this.b = vVar;
                super(c5041z3);
                break;
        }
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        Object value;
        Object value2;
        switch (this.a) {
            case 0:
                timber.log.c.a.p(th);
                boolean z = th instanceof DeleteNoteException;
                v vVar = this.b;
                if (z || (th instanceof UpdatePrivacySettingsException)) {
                    vVar.r.h(com.quizlet.features.notes.detail.events.j.a);
                    break;
                } else if (th instanceof NotFoundNotesException) {
                    vVar.getClass();
                    E.A(p0.j(vVar), null, null, new h(vVar, null), 3);
                    break;
                } else if (th instanceof UpdateTitleException) {
                    E.A(p0.j(vVar), null, null, new f(vVar, null), 3);
                    break;
                } else if (th instanceof PrivateNotesException) {
                    String strC = vVar.C();
                    com.quizlet.features.notes.logging.f fVar = vVar.f;
                    fVar.getClass();
                    NotesEventLog.Companion companion = NotesEventLog.b;
                    String strA = EnumC4465a0.NOTE_ACCESS_DENIED.a();
                    com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strC, 10);
                    EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
                    companion.getClass();
                    fVar.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
                    E.A(p0.j(vVar), null, null, new i(vVar, null), 3);
                    break;
                } else if (th instanceof ModerationException) {
                    s0 s0Var = vVar.q;
                    do {
                        value2 = s0Var.getValue();
                    } while (!s0Var.k(value2, new com.quizlet.features.notes.detail.states.e(com.quizlet.features.notes.data.n.a)));
                } else if (th instanceof NoInternetStudyNotesException) {
                    s0 s0Var2 = vVar.q;
                    do {
                        value = s0Var2.getValue();
                    } while (!s0Var2.k(value, new com.quizlet.features.notes.detail.states.e(com.quizlet.features.notes.data.p.a)));
                }
                break;
            case 1:
                v vVar2 = this.b;
                com.quizlet.features.notes.logging.f fVar2 = vVar2.f;
                String strC2 = vVar2.C();
                fVar2.getClass();
                NotesEventLog.Companion companion2 = NotesEventLog.b;
                String strA2 = EnumC4465a0.DELETE_NOTE_ERROR.a();
                com.quizlet.features.notes.logging.c cVar2 = new com.quizlet.features.notes.logging.c(strC2, 18);
                EnumC4503n enumC4503n2 = com.quizlet.features.notes.logging.a.c;
                companion2.getClass();
                fVar2.a(NotesEventLog.Companion.a(enumC4503n2, strA2, cVar2));
                vVar2.w.handleException(coroutineContext, th);
                break;
            default:
                v vVar3 = this.b;
                com.quizlet.features.notes.logging.f fVar3 = vVar3.f;
                String strC3 = vVar3.C();
                fVar3.getClass();
                NotesEventLog.Companion companion3 = NotesEventLog.b;
                String strA3 = EnumC4465a0.PRIVACY_SETTINGS_UPDATE_ERROR.a();
                androidx.navigation.internal.h hVar = new androidx.navigation.internal.h(strC3, 26);
                EnumC4503n enumC4503n3 = com.quizlet.features.notes.logging.a.c;
                companion3.getClass();
                fVar3.a(NotesEventLog.Companion.a(enumC4503n3, strA3, hVar));
                vVar3.w.handleException(coroutineContext, th);
                break;
        }
    }
}
