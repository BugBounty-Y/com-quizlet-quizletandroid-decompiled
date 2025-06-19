package com.quizlet.explanations.textbook.data;

import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class t {
    public final com.quizlet.explanations.sharing.a a;
    public final String b;
    public final ExplanationsLogger.EventData c;

    public t(com.quizlet.explanations.sharing.a aVar, String str, ExplanationsLogger.EventData eventData) {
        this.a = aVar;
        this.b = str;
        this.c = eventData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return Intrinsics.b(this.a, tVar.a) && Intrinsics.b(this.b, tVar.b) && Intrinsics.b(this.c, tVar.c);
    }

    public final int hashCode() {
        com.quizlet.explanations.sharing.a aVar = this.a;
        int iHashCode = (aVar == null ? 0 : aVar.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        ExplanationsLogger.EventData eventData = this.c;
        return iHashCode2 + (eventData != null ? eventData.hashCode() : 0);
    }

    public final String toString() {
        return "TextbookShareData(explanationsShareResData=" + this.a + ", webUrl=" + this.b + ", eventData=" + this.c + ")";
    }
}
