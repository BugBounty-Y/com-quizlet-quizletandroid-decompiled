package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.infra.studysetting.data.GradingSettingsValues;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import kotlinx.coroutines.flow.X;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public boolean A;
    public boolean B;
    public boolean C;
    public int D;
    public /* synthetic */ Object E;
    public final /* synthetic */ i F;
    public int G;
    public i j;
    public QuestionSettings k;
    public StudyableModelData l;
    public X m;
    public Object n;
    public GradingSettingsValues o;
    public com.quizlet.qutils.language.e p;
    public com.quizlet.qutils.language.e q;
    public boolean r;
    public boolean s;
    public boolean t;
    public boolean u;
    public boolean v;
    public boolean w;
    public boolean x;
    public boolean y;
    public boolean z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.F = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.E = obj;
        this.G |= Integer.MIN_VALUE;
        return i.A(this.F, null, this);
    }
}
