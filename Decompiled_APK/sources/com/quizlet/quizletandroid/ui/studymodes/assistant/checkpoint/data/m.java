package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements q {
    public final AssistantCheckpointProgressState a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final List f;
    public final boolean g;
    public final List h;
    public final com.quizlet.learn.ui.g i;
    public final com.quizlet.learn.checkpoint.data.c j;
    public final boolean k;

    public m(AssistantCheckpointProgressState progressState, int i, int i2, int i3, int i4, List enabledQuestionTypes, boolean z, List termList, com.quizlet.learn.ui.g gVar, com.quizlet.learn.checkpoint.data.c progressBarState, boolean z2) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
        Intrinsics.checkNotNullParameter(termList, "termList");
        Intrinsics.checkNotNullParameter(progressBarState, "progressBarState");
        this.a = progressState;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = enabledQuestionTypes;
        this.g = z;
        this.h = termList;
        this.i = gVar;
        this.j = progressBarState;
        this.k = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return this.a == mVar.a && this.b == mVar.b && this.c == mVar.c && this.d == mVar.d && this.e == mVar.e && Intrinsics.b(this.f, mVar.f) && this.g == mVar.g && Intrinsics.b(this.h, mVar.h) && Intrinsics.b(this.i, mVar.i) && Intrinsics.b(this.j, mVar.j) && this.k == mVar.k;
    }

    public final int hashCode() {
        int iF = d0.f(d0.g(d0.f(d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31), 31), 31, this.f), 31, this.g), 31, this.h);
        com.quizlet.learn.ui.g gVar = this.i;
        return Boolean.hashCode(this.k) + ((this.j.hashCode() + ((iF + (gVar == null ? 0 : gVar.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Detailed(progressState=");
        sb.append(this.a);
        sb.append(", roundCompleted=");
        sb.append(this.b);
        sb.append(", numberOfTermsStudied=");
        sb.append(this.c);
        sb.append(", totalProgress=");
        sb.append(this.d);
        sb.append(", totalNumberTerms=");
        sb.append(this.e);
        sb.append(", enabledQuestionTypes=");
        sb.append(this.f);
        sb.append(", firstCheckpointInSession=");
        sb.append(this.g);
        sb.append(", termList=");
        sb.append(this.h);
        sb.append(", upsellState=");
        sb.append(this.i);
        sb.append(", progressBarState=");
        sb.append(this.j);
        sb.append(", canStarTerms=");
        return android.support.v4.media.session.a.o(")", sb, this.k);
    }
}
