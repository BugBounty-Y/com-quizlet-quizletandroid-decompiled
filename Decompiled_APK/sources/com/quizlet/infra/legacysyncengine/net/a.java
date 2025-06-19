package com.quizlet.infra.legacysyncengine.net;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.eventlogger.model.AudioPlaybackCountsLog;
import com.quizlet.generated.enums.O1;
import io.reactivex.rxjava3.subjects.p;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Object next;
        Long serverSetId;
        switch (this.a) {
            case 0:
                List list = (List) obj;
                c cVar = (c) this.b;
                cVar.getClass();
                int size = list.size();
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar = cVar.b;
                if (size > 0) {
                    dVar.c.forEach(1L, new com.quizlet.infra.legacysyncengine.net.listeners.b(dVar, list, false));
                } else {
                    IdMappedQuery idMappedQueryConvertStaleLocalIds = dVar.b.convertStaleLocalIds((com.quizlet.infra.legacysyncengine.orm.query.a) this.c);
                    com.quizlet.infra.legacysyncengine.e eVar = dVar.a;
                    eVar.b.compute(idMappedQueryConvertStaleLocalIds, new com.quizlet.infra.legacysyncengine.b(0));
                    ArrayList arrayListA = eVar.a(idMappedQueryConvertStaleLocalIds);
                    if (arrayListA != null && arrayListA.isEmpty()) {
                        com.quizlet.infra.legacysyncengine.net.listeners.d.a(arrayListA, (List) dVar.c.getOrDefault(idMappedQueryConvertStaleLocalIds, new ArrayList()));
                    }
                }
                if (!((Set) this.d).contains(b.b)) {
                    ((p) this.e).b(com.quizlet.infra.legacysyncengine.net.request.c.b);
                    break;
                }
                break;
            default:
                com.quizlet.quizletandroid.ui.common.adapter.presenter.e eVar2 = (com.quizlet.quizletandroid.ui.common.adapter.presenter.e) this.b;
                com.quizlet.quizletandroid.managers.audio.b bVar = eVar2.e;
                bVar.getClass();
                O1 termSide = (O1) this.e;
                Intrinsics.checkNotNullParameter(termSide, "termSide");
                DBTerm term = (DBTerm) this.d;
                Intrinsics.checkNotNullParameter(term, "term");
                long setId = term.getSetId();
                String language = term.getLanguageCode(termSide);
                if (language != null) {
                    boolean zA = com.quizlet.quizletandroid.managers.audio.b.a(term, termSide);
                    HashSet hashSet = bVar.a;
                    Iterator it2 = hashSet.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            next = it2.next();
                            AudioPlaybackCountsLog audioPlaybackCountsLog = (AudioPlaybackCountsLog) next;
                            audioPlaybackCountsLog.getClass();
                            Intrinsics.checkNotNullParameter(language, "language");
                            if (audioPlaybackCountsLog.getPayload().getStudySessionId() != null || audioPlaybackCountsLog.getPayload().getStudyMode() != null || audioPlaybackCountsLog.getPayload().getServerSetId() == null || (serverSetId = audioPlaybackCountsLog.getPayload().getServerSetId()) == null || serverSetId.longValue() != setId || !language.equals(audioPlaybackCountsLog.getPayload().getLanguage()) || audioPlaybackCountsLog.getPayload().getErrors() != null) {
                            }
                        } else {
                            next = null;
                        }
                    }
                    AudioPlaybackCountsLog audioPlaybackCountsLogA = (AudioPlaybackCountsLog) next;
                    if (audioPlaybackCountsLogA == null) {
                        AudioPlaybackCountsLog.b.getClass();
                        audioPlaybackCountsLogA = AudioPlaybackCountsLog.Companion.a(setId, language);
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
                eVar2.f = new androidx.core.util.c(Long.valueOf(term.getId()), termSide);
                ((com.quizlet.quizletandroid.ui.common.adapter.presenter.d) this.c).e(term);
                break;
        }
    }
}
