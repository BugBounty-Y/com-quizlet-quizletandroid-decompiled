package com.features.flashcards.creatormarketing;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.AndroidEventPayload;
import com.quizlet.eventlogger.model.ProgressEventBucketData;
import com.quizlet.eventlogger.model.QuestionEventLog;
import com.quizlet.generated.enums.O1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h {
    public final EventLogger a;

    public h(EventLogger eventLogger, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 3:
                this.a = eventLogger;
                break;
            default:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.List] */
    public static void a(AndroidEventLog androidEventLog, com.quizlet.features.setpage.progress.b bVar) {
        if (bVar.b() != 0) {
            AndroidEventPayload payload = androidEventLog.getPayload();
            List list = bVar.a;
            payload.setNotStudied(new ProgressEventBucketData((list.size() * 100) / bVar.b(), list.size()));
            AndroidEventPayload payload2 = androidEventLog.getPayload();
            List list2 = bVar.b;
            payload2.setStillLearning(new ProgressEventBucketData((list2.size() * 100) / bVar.b(), list2.size()));
            AndroidEventPayload payload3 = androidEventLog.getPayload();
            ?? r1 = bVar.c;
            payload3.setMastered(new ProgressEventBucketData((r1.size() * 100) / bVar.b(), r1.size()));
        }
    }

    public static boolean b(DBTerm dBTerm, O1 o1) {
        return o1 == O1.DEFINITION && dBTerm.hasDefinitionImage();
    }

    public void c(String str, String str2, String str3, DBTerm dBTerm, O1 o1, Boolean bool, Integer num, String str4, Integer num2) {
        O1 o12 = O1.WORD;
        O1 o13 = o1 == o12 ? O1.DEFINITION : o12;
        Integer numValueOf = bool != null ? Integer.valueOf(bool.booleanValue() ? 1 : 0) : null;
        Long lValueOf = dBTerm.getId() >= 0 ? Long.valueOf(dBTerm.getId()) : null;
        long localId = dBTerm.getLocalId();
        int iIntValue = num.intValue();
        boolean zD = org.apache.commons.lang3.e.d(dBTerm.getText(o1));
        boolean zB = b(dBTerm, o1);
        boolean zHasWordAudio = o1 == o12 ? dBTerm.hasWordAudio() : dBTerm.hasDefinitionAudio();
        boolean zD2 = org.apache.commons.lang3.e.d(dBTerm.getText(o13));
        boolean zB2 = b(dBTerm, o13);
        boolean zHasWordAudio2 = o13 == o12 ? dBTerm.hasWordAudio() : dBTerm.hasDefinitionAudio();
        QuestionEventLog.b.getClass();
        this.a.v(QuestionEventLog.Companion.a(str3, str, str2, lValueOf, localId, iIntValue, zD, zB, zHasWordAudio, zD2, zB2, zHasWordAudio2, null, o1, numValueOf, str4, num2, "", null, null, null, null, null, null));
    }
}
