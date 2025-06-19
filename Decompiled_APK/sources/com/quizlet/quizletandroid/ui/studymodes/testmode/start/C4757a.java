package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.testmode.start.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4757a {
    public final j a;
    public final j b;
    public final j c;
    public final j d;
    public final j e;
    public final j f;
    public final com.quizlet.qutils.string.g g;
    public final com.quizlet.qutils.string.g h;

    public C4757a(j answerTermSwitchData, j answerDefinitionSwitchData, j jVar, j promptTermSwitchData, j promptDefinitionSwitchData, j jVar2, com.quizlet.qutils.string.g termStringData, com.quizlet.qutils.string.g definitionStringData) {
        Intrinsics.checkNotNullParameter(answerTermSwitchData, "answerTermSwitchData");
        Intrinsics.checkNotNullParameter(answerDefinitionSwitchData, "answerDefinitionSwitchData");
        Intrinsics.checkNotNullParameter(promptTermSwitchData, "promptTermSwitchData");
        Intrinsics.checkNotNullParameter(promptDefinitionSwitchData, "promptDefinitionSwitchData");
        Intrinsics.checkNotNullParameter(termStringData, "termStringData");
        Intrinsics.checkNotNullParameter(definitionStringData, "definitionStringData");
        this.a = answerTermSwitchData;
        this.b = answerDefinitionSwitchData;
        this.c = jVar;
        this.d = promptTermSwitchData;
        this.e = promptDefinitionSwitchData;
        this.f = jVar2;
        this.g = termStringData;
        this.h = definitionStringData;
    }

    public static C4757a a(C4757a c4757a, j jVar, j jVar2, j jVar3, j jVar4, j jVar5, j jVar6, int i) {
        if ((i & 1) != 0) {
            jVar = c4757a.a;
        }
        j answerTermSwitchData = jVar;
        if ((i & 2) != 0) {
            jVar2 = c4757a.b;
        }
        j answerDefinitionSwitchData = jVar2;
        if ((i & 4) != 0) {
            jVar3 = c4757a.c;
        }
        j jVar7 = jVar3;
        if ((i & 8) != 0) {
            jVar4 = c4757a.d;
        }
        j promptTermSwitchData = jVar4;
        j promptDefinitionSwitchData = (i & 16) != 0 ? c4757a.e : jVar5;
        j jVar8 = (i & 32) != 0 ? c4757a.f : jVar6;
        com.quizlet.qutils.string.g termStringData = c4757a.g;
        com.quizlet.qutils.string.g definitionStringData = c4757a.h;
        c4757a.getClass();
        Intrinsics.checkNotNullParameter(answerTermSwitchData, "answerTermSwitchData");
        Intrinsics.checkNotNullParameter(answerDefinitionSwitchData, "answerDefinitionSwitchData");
        Intrinsics.checkNotNullParameter(promptTermSwitchData, "promptTermSwitchData");
        Intrinsics.checkNotNullParameter(promptDefinitionSwitchData, "promptDefinitionSwitchData");
        Intrinsics.checkNotNullParameter(termStringData, "termStringData");
        Intrinsics.checkNotNullParameter(definitionStringData, "definitionStringData");
        return new C4757a(answerTermSwitchData, answerDefinitionSwitchData, jVar7, promptTermSwitchData, promptDefinitionSwitchData, jVar8, termStringData, definitionStringData);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4757a)) {
            return false;
        }
        C4757a c4757a = (C4757a) obj;
        return Intrinsics.b(this.a, c4757a.a) && Intrinsics.b(this.b, c4757a.b) && Intrinsics.b(this.c, c4757a.c) && Intrinsics.b(this.d, c4757a.d) && Intrinsics.b(this.e, c4757a.e) && Intrinsics.b(this.f, c4757a.f) && Intrinsics.b(this.g, c4757a.g) && Intrinsics.b(this.h, c4757a.h);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        j jVar = this.c;
        int iHashCode2 = (this.e.hashCode() + ((this.d.hashCode() + ((iHashCode + (jVar == null ? 0 : jVar.hashCode())) * 31)) * 31)) * 31;
        j jVar2 = this.f;
        return this.h.hashCode() + ((this.g.hashCode() + ((iHashCode2 + (jVar2 != null ? jVar2.hashCode() : 0)) * 31)) * 31);
    }

    public final String toString() {
        return "AnswerPromptConfiguration(answerTermSwitchData=" + this.a + ", answerDefinitionSwitchData=" + this.b + ", answerLocationSwitchData=" + this.c + ", promptTermSwitchData=" + this.d + ", promptDefinitionSwitchData=" + this.e + ", promptLocationSwitchData=" + this.f + ", termStringData=" + this.g + ", definitionStringData=" + this.h + ")";
    }
}
