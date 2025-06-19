package com.quizlet.quizletandroid.managers.audio;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.O1;
import java.util.HashSet;

/* loaded from: classes3.dex */
public final class b {
    public final HashSet a = new HashSet();

    public static boolean a(DBTerm dBTerm, O1 o1) {
        int i = a.a[o1.ordinal()];
        if (i != 1) {
            if (i != 2 || dBTerm.getDefinitionCustomAudioId() == null || dBTerm.getDefinitionCustomAudioId().longValue() <= 0) {
                return false;
            }
        } else if (dBTerm.getWordCustomAudioId() == null || dBTerm.getWordCustomAudioId().longValue() <= 0) {
            return false;
        }
        return true;
    }
}
