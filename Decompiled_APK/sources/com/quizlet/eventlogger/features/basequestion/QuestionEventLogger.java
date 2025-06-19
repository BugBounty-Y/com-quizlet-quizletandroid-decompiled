package com.quizlet.eventlogger.features.basequestion;

import assistantMode.enums.k;
import com.google.android.gms.ads.g;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public interface QuestionEventLogger {

    @Metadata
    public static final class DefaultImpls {
        public static /* synthetic */ void a(QuestionEventLogger questionEventLogger, String str, String str2, QuestionEventLogData questionEventLogData, int i, Integer num, String str3, O1 o1, String str4, A1 a1, k kVar, int i2) {
            if ((i2 & 128) != 0) {
                str4 = null;
            }
            if ((i2 & g.MAX_CONTENT_URL_LENGTH) != 0) {
                a1 = null;
            }
            if ((i2 & 1024) != 0) {
                kVar = null;
            }
            questionEventLogger.a(str, str2, questionEventLogData, i, num, str3, o1, str4, a1, kVar);
        }
    }

    void a(String str, String str2, QuestionEventLogData questionEventLogData, int i, Integer num, String str3, O1 o1, String str4, A1 a1, k kVar);
}
