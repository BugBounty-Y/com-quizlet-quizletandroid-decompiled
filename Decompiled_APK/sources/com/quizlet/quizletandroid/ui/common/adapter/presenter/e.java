package com.quizlet.quizletandroid.ui.common.adapter.presenter;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.model.AudioPlaybackCountsLog;
import com.quizlet.generated.enums.O1;
import com.quizlet.infra.legacysyncengine.net.f;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.managers.audio.h;
import com.quizlet.quizletandroid.util.QLocalizedException;
import io.reactivex.rxjava3.internal.operators.completable.i;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final com.quizlet.infra.legacysyncengine.managers.d a;
    public final f b;
    public final h c;
    public final com.quizlet.quizletandroid.ui.common.adapter.e d;
    public final com.quizlet.quizletandroid.managers.audio.b e = new com.quizlet.quizletandroid.managers.audio.b();
    public androidx.core.util.c f;
    public final io.ktor.client.plugins.api.d g;
    public io.reactivex.rxjava3.internal.observers.e h;

    public e(com.quizlet.infra.legacysyncengine.managers.d dVar, f fVar, h hVar, com.quizlet.quizletandroid.ui.common.adapter.e eVar, io.ktor.client.plugins.api.d dVar2) {
        this.a = dVar;
        this.b = fVar;
        this.c = hVar;
        this.d = eVar;
        this.g = dVar2;
    }

    public final O1 a(DBTerm dBTerm) {
        if (this.f == null || dBTerm.getId() != ((Long) this.f.a).longValue()) {
            return null;
        }
        return (O1) this.f.b;
    }

    public final void b(DBTerm dBTerm, DBSelectedTerm dBSelectedTerm, int i) {
        f fVar = this.b;
        if (dBSelectedTerm == null) {
            fVar.a(new DBSelectedTerm(this.a.e.getPersonId(), dBTerm.getSetId(), dBTerm.getId(), System.currentTimeMillis() / 1000, i));
        } else {
            dBSelectedTerm.setDeleted(true);
            fVar.a(dBSelectedTerm);
        }
    }

    public final void c(final Context context, final d dVar, final DBTerm dBTerm, final O1 o1, final boolean z) {
        if (dBTerm == null) {
            return;
        }
        androidx.core.util.c cVar = this.f;
        h hVar = this.c;
        if (cVar != null && ((Long) cVar.a).longValue() == dBTerm.getId() && (this.f.b == o1 || z)) {
            hVar.b(true);
            io.reactivex.rxjava3.internal.observers.e eVar = this.h;
            if (eVar != null && !eVar.b()) {
                io.reactivex.rxjava3.internal.disposables.a.a(eVar);
            }
            this.f = null;
            return;
        }
        if (org.apache.commons.lang3.e.c(dBTerm.getAudioUrl(o1))) {
            if (!z) {
                this.g.w(dBTerm, o1);
                return;
            }
            O1 o12 = O1.WORD;
            if (o1 == o12) {
                o12 = O1.DEFINITION;
            }
            c(context, dVar, dBTerm, o12, false);
            return;
        }
        String audioUrl = dBTerm.getAudioUrl(o1);
        if (audioUrl == null) {
            return;
        }
        io.reactivex.rxjava3.internal.observers.e eVar2 = this.h;
        if (eVar2 != null && !eVar2.b()) {
            io.reactivex.rxjava3.internal.disposables.a.a(eVar2);
        }
        io.reactivex.rxjava3.internal.operators.completable.a aVarA = hVar.a(audioUrl);
        com.quizlet.infra.legacysyncengine.net.a aVar = new com.quizlet.infra.legacysyncengine.net.a(this, dVar, dBTerm, o1, 1);
        g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        this.h = new i(new i(aVarA, aVar, gVar, bVar, bVar), gVar, gVar, bVar, new a(this, dVar, dBTerm, 0)).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.common.adapter.presenter.b
            @Override // io.reactivex.rxjava3.functions.a
            public final void run() {
                e eVar3 = this.a;
                eVar3.f = null;
                d dVar2 = dVar;
                DBTerm dBTerm2 = dBTerm;
                dVar2.e(dBTerm2);
                if (z) {
                    O1 o13 = O1.WORD;
                    if (o1 == o13) {
                        o13 = O1.DEFINITION;
                    }
                    eVar3.c(context, dVar2, dBTerm2, o13, false);
                }
            }
        }, new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.ui.common.adapter.presenter.c
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i;
                Object next;
                Long serverSetId;
                Throwable th = (Throwable) obj;
                e eVar3 = this.a;
                if (th instanceof QLocalizedException) {
                    i = ((QLocalizedException) th).a;
                } else {
                    timber.log.c.a(th);
                    i = R.string.failed_to_play_audio;
                }
                eVar3.f = null;
                d dVar2 = dVar;
                DBTerm term = dBTerm;
                dVar2.e(term);
                Context context2 = context;
                String errorMsg = (i == 0 || i == R.string.empty) ? context2.getString(R.string.could_not_play) : context2.getString(i);
                com.quizlet.quizletandroid.managers.audio.b bVar2 = eVar3.e;
                bVar2.getClass();
                O1 termSide = o1;
                Intrinsics.checkNotNullParameter(termSide, "termSide");
                Intrinsics.checkNotNullParameter(term, "term");
                Intrinsics.checkNotNullParameter(errorMsg, "errorMsg");
                long setId = term.getSetId();
                String language = term.getLanguageCode(termSide);
                if (language != null) {
                    boolean zA = com.quizlet.quizletandroid.managers.audio.b.a(term, termSide);
                    HashSet hashSet = bVar2.a;
                    Iterator it2 = hashSet.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            next = null;
                            break;
                        }
                        next = it2.next();
                        AudioPlaybackCountsLog audioPlaybackCountsLog = (AudioPlaybackCountsLog) next;
                        audioPlaybackCountsLog.getClass();
                        Intrinsics.checkNotNullParameter(language, "language");
                        Intrinsics.checkNotNullParameter(errorMsg, "errorMsg");
                        if (audioPlaybackCountsLog.getPayload().getStudySessionId() == null && audioPlaybackCountsLog.getPayload().getStudyMode() == null && audioPlaybackCountsLog.getPayload().getServerSetId() != null && (serverSetId = audioPlaybackCountsLog.getPayload().getServerSetId()) != null && serverSetId.longValue() == setId && language.equals(audioPlaybackCountsLog.getPayload().getLanguage()) && Intrinsics.b(errorMsg, audioPlaybackCountsLog.getPayload().getErrors())) {
                            break;
                        }
                    }
                    AudioPlaybackCountsLog audioPlaybackCountsLogA = (AudioPlaybackCountsLog) next;
                    if (audioPlaybackCountsLogA == null) {
                        AudioPlaybackCountsLog.b.getClass();
                        audioPlaybackCountsLogA = AudioPlaybackCountsLog.Companion.a(setId, language);
                        Intrinsics.checkNotNullParameter(errorMsg, "errorMsg");
                        audioPlaybackCountsLogA.getPayload().setErrors(errorMsg);
                    }
                    hashSet.add(audioPlaybackCountsLogA);
                    if (zA) {
                        AudioPlaybackCountsLog.AudioPlayBackCountsPayload payload = audioPlaybackCountsLogA.getPayload();
                        Integer customAudioCount = audioPlaybackCountsLogA.getPayload().getCustomAudioCount();
                        payload.setCustomAudioCount(Integer.valueOf((customAudioCount != null ? customAudioCount.intValue() : 0) + 1));
                    } else {
                        AudioPlaybackCountsLog.AudioPlayBackCountsPayload payload2 = audioPlaybackCountsLogA.getPayload();
                        Integer ttsCount = audioPlaybackCountsLogA.getPayload().getTtsCount();
                        payload2.setTtsCount(Integer.valueOf((ttsCount != null ? ttsCount.intValue() : 0) + 1));
                    }
                }
                AbstractC3125d6.d(context2, errorMsg);
                if (z) {
                    O1 o13 = O1.WORD;
                    if (termSide == o13) {
                        o13 = O1.DEFINITION;
                    }
                    eVar3.c(context2, dVar2, term, o13, false);
                }
            }
        });
    }
}
